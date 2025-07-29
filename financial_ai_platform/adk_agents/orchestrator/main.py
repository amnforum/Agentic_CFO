import asyncio
import os
import json
import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
import httpx
import google.generativeai as genai
from dotenv import load_dotenv
from .config import MCP_SERVERS, MCP_API_PATHS, AGENT_API_MAP

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="ADK Orchestrator", version="1.1")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    logger.info(f"Gemini API Key configured for model {GEMINI_MODEL}")
else:
    logger.warning("Gemini API Key NOT set. LLM features will be unavailable.")

class ChatRequest(BaseModel):
    message: str
    user_context: dict

class AgentResponse(BaseModel):
    agent: str
    response: str
    data: dict
    confidence: float

class OrchestrationResponse(BaseModel):
    query: str
    selected_agents: list
    responses: list
    final_answer: str
    timestamp: str

async def fetch_mcp(api: str, phone: str) -> dict:
    url = f"{MCP_SERVERS['fi_mcp']}{MCP_API_PATHS[api]}"
    headers = {"X-Phone-Number": phone}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.error(f"Error fetching {api}: {e}")
        return {"error": str(e)}

async def extract_tax_inputs(net_worth, mf, bank, credit, epf, stocks):
    income = 0
    deductions = {"section_80c": 0, "section_80d": 0}
    # 1. Salary and interest
    for txn in bank.get("transactions", []):
        desc = str(txn.get("description", "")).lower()
        amount = float(txn.get("amount", 0) or 0)
        if any(word in desc for word in ["salary", "credit", "pay"]) and amount > 0:
            income += amount
        if "insurance" in desc and amount < 0:
            deductions["section_80d"] += abs(amount)
        if "interest" in desc and amount > 0:
            income += amount
    # 2. ELSS SIP MF for 80C
    for txn in mf.get("transactions", []):
        scheme = str(txn.get("schemeName", "")).lower()
        amount = float(txn.get("amount", 0) or 0)
        if "elss" in scheme or "tax" in scheme:
            deductions["section_80c"] += amount
    # 3. EPF (employee) for 80C
    deductions["section_80c"] += float(epf.get("employeeContribution", 0) or 0)
    investments = {} # Extend in future if needed
    return income, investments, deductions

def select_agents(query: str) -> list:
    q = query.lower()
    agents = []
    if any(w in q for w in ["net worth", "wealth", "portfolio", "assets"]):
        agents.append("portfolio_manager")
    if any(w in q for w in ["spending", "budget", "expense", "cash flow", "bank"]):
        agents.append("budget_planner")
    if any(w in q for w in ["credit", "loan", "debt"]):
        agents.append("credit_monitor")
    if any(w in q for w in ["investment", "mutual fund", "sip", "market", "stocks"]):
        agents.append("investment_analyst")
    if any(w in q for w in ["risk", "insurance"]):
        agents.append("risk_assessor")
    if any(w in q for w in ["tax", "itr", "income tax", "deduction"]):
        agents.append("tax_accountant")
    return list(set(agents)) or ["portfolio_manager"]

async def summarize_agent(agent: str, user_ctx: dict) -> AgentResponse:
    phone = user_ctx.get("phone_number", "")
    data = {}
    if agent == "tax_accountant":
        # Fetch all required MCP endpoints concurrently (FAST)
        fetches = [
            fetch_mcp("net_worth", phone),
            fetch_mcp("mutual_funds", phone),
            fetch_mcp("bank", phone),
            fetch_mcp("credit_report", phone),
            fetch_mcp("epf", phone),
            fetch_mcp("stocks", phone),
        ]
        net_worth, mf, bank, credit, epf, stocks = await asyncio.gather(*fetches)
        income, investments, deductions = await extract_tax_inputs(net_worth, mf, bank, credit, epf, stocks)
        # New regime tax slab
        taxable_income = max(0, income - deductions.get("section_80c", 0) - deductions.get("section_80d", 0))
        tax = 0
        if taxable_income > 1500000:
            tax = (
                0.05 * min(300000, taxable_income - 250000) +
                0.1 * min(600000, max(0, taxable_income - 500000)) +
                0.15 * min(300000, max(0, taxable_income - 900000)) +
                0.20 * min(300000, max(0, taxable_income - 1200000)) +
                0.30 * max(0, taxable_income - 1500000)
            )
        elif taxable_income > 1200000:
            tax = (
                0.05 * min(300000, taxable_income - 250000) +
                0.1 * min(600000, max(0, taxable_income - 500000)) +
                0.15 * min(300000, max(0, taxable_income - 900000)) +
                0.20 * min(300000, max(0, taxable_income - 1200000))
            )
        elif taxable_income > 900000:
            tax = (
                0.05 * min(300000, taxable_income - 250000) +
                0.1 * min(600000, max(0, taxable_income - 500000)) +
                0.15 * min(300000, max(0, taxable_income - 900000))
            )
        elif taxable_income > 600000:
            tax = (
                0.05 * min(300000, taxable_income - 250000) +
                0.1 * min(600000, max(0, taxable_income - 500000))
            )
        elif taxable_income > 300000:
            tax = 0.05 * min(300000, taxable_income - 250000)
        tax = round(tax)
        cess = 0.04 * tax
        total_tax = round(tax + cess)
        summary_data = {
            "annual_income": income,
            "deductions": deductions,
            "taxable_income": taxable_income,
            "gross_tax": int(tax),
            "cess": int(cess),
            "total_tax_payable": int(total_tax),
        }
        prompt = (
            f"User Query: {user_ctx.get('query', '')}\n"
            f"Summary Data: {json.dumps(summary_data, indent=2)}\n"
            "Create a tax summary showing key values and a stepwise checklist for ITR upload (List 'documents needed' and suggest further savings if possible)."
        )
        if GEMINI_API_KEY:
            model = genai.GenerativeModel(GEMINI_MODEL)
            res = model.generate_content(prompt)
            return AgentResponse(agent=agent, response=res.text, data=summary_data, confidence=0.99)
        else:
            return AgentResponse(agent=agent, response=f"Tax calculation: {summary_data}", data=summary_data, confidence=0.5)
    else:
        for api in AGENT_API_MAP.get(agent, []):
            data[api] = await fetch_mcp(api, phone)
        summary = {k: (len(v['transactions']) if isinstance(v, dict) and 'transactions' in v else v)
                   for k, v in data.items()}
        if GEMINI_API_KEY:
            model = genai.GenerativeModel(GEMINI_MODEL)
            prompt = (
                f"You are the '{agent.replace('_', ' ').title()}' agent. "
                f"User Query: {user_ctx.get('query','')}\n"
                f"Summary Data: {json.dumps(summary, indent=2)}\n"
                f"Provide only the relevant output answering the user. "
                f"Use KPIs, numbers, and actionable advice—no static values or generic statements."
            )
            res = model.generate_content(prompt)
            return AgentResponse(agent=agent, response=res.text, data=summary, confidence=0.9)
        else:
            return AgentResponse(agent=agent, response=f"LLM unavailable. Data: {summary}", data=summary, confidence=0.5)

@app.post("/api/chat")
async def chat_with_agents(req: ChatRequest):
    user_ctx = req.user_context or {}
    user_ctx['query'] = req.message
    phone = user_ctx.get("phone_number")
    if not phone:
        raise HTTPException(status_code=400, detail="phone_number missing in user_context.")
    agents = select_agents(req.message)
    tasks = [summarize_agent(agent, user_ctx) for agent in agents]
    agent_responses = await asyncio.gather(*tasks)
    if GEMINI_API_KEY:
        model = genai.GenerativeModel(GEMINI_MODEL)
        combined = "\n\n".join([f"{ar.agent}: {ar.response}" for ar in agent_responses])
        final_prompt = (
            f"User Query: {req.message}\nAgent Summaries:\n{combined}\n"
            "Give a unified, high-quality report tailored to the query."
        )
        try:
            final_answer = model.generate_content(final_prompt).text
        except Exception as e:
            final_answer = f"LLM error: {e}. Raw agent responses:\n{combined}"
    else:
        final_answer = "\n\n".join([f"{ar.agent}: {ar.response}" for ar in agent_responses])
    return OrchestrationResponse(
        query=req.message,
        selected_agents=agents,
        responses=[ar.dict() for ar in agent_responses],
        final_answer=final_answer,
        timestamp=datetime.now().isoformat()
    )

@app.get("/")
async def root():
    return {"message": "ADK Orchestrator REST API is live."}

@app.get("/api/health")
async def health_check():
    return {"orchestrator": "healthy", "time": datetime.now().isoformat()}

@app.get("/api/agents")
async def agents_list():
    return {"agents": list(AGENT_API_MAP.keys())}
