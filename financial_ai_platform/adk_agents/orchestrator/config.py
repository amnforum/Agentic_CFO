import os


MCP_SERVERS = {
    "fi_mcp": f"http://localhost:{os.getenv('FI_MCP_PORT', '3001')}",
}


MCP_API_PATHS = {
    "net_worth": "/api/fetch-net-worth",
    "mutual_funds": "/api/fetch-mutual-fund-transactions",
    "credit_report": "/api/fetch-credit-report",
    "epf": "/api/fetch-epf-details",
    "bank": "/api/fetch-bank-transactions",
    "stocks": "/api/fetch-stock-transactions",
}


AGENT_API_MAP = {
    "portfolio_manager":    ["net_worth", "mutual_funds", "stocks"],
    "budget_planner":       ["bank"],
    "credit_monitor":       ["credit_report"],
    "investment_analyst":   ["mutual_funds", "stocks"],
    "risk_assessor":        ["credit_report", "net_worth"],
    "tax_accountant":       ["net_worth", "mutual_funds", "epf", "credit_report", "bank", "stocks"],
}
