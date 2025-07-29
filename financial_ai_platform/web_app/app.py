#!/usr/bin/env python3
"""
Financial AI Platform Web Application - Fixed Alpaca API Integration
"""

import os
import json
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from werkzeug.security import generate_password_hash, check_password_hash
import httpx
import asyncio
from dotenv import load_dotenv
import requests
import re

from database.models import TaxReturn
## register user
from flask import Flask, render_template, request, flash, redirect, url_for, session
#########

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import database models
try:
    from database.models import db, init_db, User, ChatSession
except ImportError as e:
    logger.error(f"Database import error: {e}")
    # Fallback models
    db = SQLAlchemy()
    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        password_hash = db.Column(db.String(255), nullable=False)
        phone_number = db.Column(db.String(15), nullable=True)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        def check_password(self, pw): return check_password_hash(self.password_hash, pw)
    
    class ChatSession(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        query = db.Column(db.Text, nullable=False)
        response = db.Column(db.Text, nullable=False)
        timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def init_db(app):
        db.init_app(app)
        with app.app_context(): 
            db.create_all()

# Trading Client Class - FIXED VERSION
class AlpacaTradingClient:
    def __init__(self):
        # Use the correct paper trading base URL
        self.base_url = "https://paper-api.alpaca.markets/v2"
        self.api_key = os.getenv("ALPACA_API_KEY")
        self.secret_key = os.getenv("ALPACA_SECRET_KEY")
        
        # Validate API keys
        if not self.api_key or not self.secret_key:
            logger.error("❌ Alpaca API keys not found in environment variables")
            raise ValueError("Alpaca API keys not configured")
        
        # Fixed headers format
        self.headers = {
            "APCA-API-KEY-ID": self.api_key.strip(),
            "APCA-API-SECRET-KEY": self.secret_key.strip(),
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        logger.info(f"✅ Alpaca client initialized with API key: {self.api_key[:8]}...")
        
        # Test connection on initialization
        self._test_connection()
    
    def _test_connection(self):
        """Test API connection on initialization"""
        logger.info("🔧 Testing Alpaca API connection...")
        try:
            response = requests.get(f"{self.base_url}/account", headers=self.headers, timeout=10)
            logger.info(f"Connection test response: {response.status_code}")
            
            if response.status_code == 200:
                logger.info("✅ Alpaca API connection successful")
                account_data = response.json()
                logger.info(f"Account Status: {account_data.get('status', 'unknown')}")
                return True
            elif response.status_code == 401:
                logger.error("❌ Authentication failed - Invalid API credentials")
                logger.error("Please check your ALPACA_API_KEY and ALPACA_SECRET_KEY")
                return False
            elif response.status_code == 403:
                logger.error("❌ Access forbidden - Account may not be authorized for trading")
                logger.error("Please check your Alpaca account permissions")
                return False
            else:
                logger.error(f"❌ Alpaca API connection failed: {response.status_code}")
                logger.error(f"Response: {response.text}")
                return False
        except requests.exceptions.Timeout:
            logger.error("❌ Connection timeout - Please check your internet connection")
            return False
        except requests.exceptions.ConnectionError:
            logger.error("❌ Connection error - Cannot reach Alpaca API servers")
            return False
        except Exception as e:
            logger.error(f"❌ Alpaca API connection test failed: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            return False
    
    def _make_request(self, method: str, endpoint: str, data: dict = None):
        """Centralized request method with better error handling"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        try:
            # Log the request for debugging
            logger.info(f"Making {method.upper()} request to: {url}")
            logger.info(f"Headers: {dict(self.headers)}")
            if data:
                logger.info(f"Payload: {json.dumps(data, indent=2)}")
            
            if method.upper() == "GET":
                response = requests.get(url, headers=self.headers, timeout=30)
            elif method.upper() == "POST":
                response = requests.post(url, headers=self.headers, json=data, timeout=30)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=self.headers, timeout=30)
            else:
                return {"status": "error", "message": f"Unsupported HTTP method: {method}"}
            
            # Log response for debugging
            logger.info(f"Response Status: {response.status_code}")
            logger.info(f"Response Text: {response.text[:500]}...")
            
            # Handle different status codes
            if response.status_code == 200:
                return {"status": "success", "data": response.json()}
            elif response.status_code == 201:
                return {"status": "success", "data": response.json()}
            elif response.status_code == 204:
                return {"status": "success", "message": "Request completed successfully"}
            elif response.status_code == 401:
                return {"status": "error", "message": "Invalid API credentials. Please check your API keys."}
            elif response.status_code == 403:
                return {"status": "error", "message": "Access forbidden. Account may not be authorized for trading."}
            elif response.status_code == 422:
                error_data = response.json()
                error_msg = error_data.get('message', 'Unprocessable entity')
                return {"status": "error", "message": f"Validation error: {error_msg}"}
            elif response.status_code == 429:
                return {"status": "error", "message": "Rate limit exceeded. Please try again later."}
            else:
                try:
                    error_data = response.json()
                    error_msg = error_data.get('message', response.text)
                except:
                    error_msg = response.text
                return {"status": "error", "message": f"HTTP {response.status_code}: {error_msg}"}
                
        except requests.exceptions.Timeout:
            return {"status": "error", "message": "Request timeout. Please try again."}
        except requests.exceptions.ConnectionError:
            return {"status": "error", "message": "Connection error. Please check your internet connection."}
        except Exception as e:
            logger.error(f"Request error: {str(e)}")
            return {"status": "error", "message": f"Request failed: {str(e)}"}
    
    def place_order(self, symbol: str, qty: int, side: str, order_type="market"):
        """Place a buy/sell order with improved error handling"""
        if not symbol or qty <= 0:
            return {"status": "error", "message": "Invalid symbol or quantity"}
        
        payload = {
            "symbol": symbol.upper().strip(),
            "qty": str(qty),
            "side": side.lower(),
            "type": order_type,
            "time_in_force": "day"
        }
        
        return self._make_request("POST", "/orders", payload)
    
    def get_account(self):
        """Get account information"""
        return self._make_request("GET", "/account")
    
    def get_positions(self):
        """Get current positions"""
        return self._make_request("GET", "/positions")
    
    def get_orders(self, status="all"):
        """Get order history"""
        endpoint = f"/orders?status={status}&limit=50"
        return self._make_request("GET", endpoint)
    
    def cancel_order(self, order_id: str):
        """Cancel an order"""
        return self._make_request("DELETE", f"/orders/{order_id}")
    
    def get_portfolio_history(self):
        """Get portfolio history"""
        return self._make_request("GET", "/account/portfolio/history")
    
    def get_market_data(self, symbol: str):
        """Get latest market data for a symbol"""
        endpoint = f"/stocks/{symbol.upper()}/quotes/latest"
        return self._make_request("GET", endpoint)

# Initialize trading client with better error handling
trading_client = None

def initialize_trading_client():
    """Initialize trading client with detailed error reporting"""
    global trading_client
    
    # Check environment variables first
    api_key = os.getenv("ALPACA_API_KEY")
    secret_key = os.getenv("ALPACA_SECRET_KEY")
    
    logger.info("🔧 Checking Alpaca API Configuration...")
    logger.info(f"API Key present: {bool(api_key)}")
    logger.info(f"Secret Key present: {bool(secret_key)}")
    
    if api_key:
        logger.info(f"API Key prefix: {api_key[:8]}...")
    else:
        logger.error("❌ ALPACA_API_KEY environment variable not set")
        return False
    
    if secret_key:
        logger.info(f"Secret Key prefix: {secret_key[:8]}...")  
    else:
        logger.error("❌ ALPACA_SECRET_KEY environment variable not set")
        return False
    
    try:
        logger.info("🔧 Initializing Alpaca Trading Client...")
        trading_client = AlpacaTradingClient()
        logger.info("✅ Trading client initialized successfully")
        return True
    except ValueError as e:
        logger.error(f"❌ Trading client initialization failed - Configuration Error: {e}")
        trading_client = None
        return False
    except Exception as e:
        logger.error(f"❌ Trading client initialization failed - Unexpected Error: {e}")
        logger.error(f"Error type: {type(e).__name__}")
        trading_client = None
        return False

# Initialize the trading client
logger.info("🚀 Initializing Trading Client...")
trading_client_initialized = initialize_trading_client()

# Trading Functions
def buy_stock(symbol: str, quantity: int) -> dict:
    """Buy stocks with specified quantity"""
    global trading_client
    
    if not trading_client:
        logger.error("Trading client not available in buy_stock function")
        return {"status": "error", "message": "Trading client not available"}
    
    if quantity <= 0:
        return {"status": "error", "message": "Quantity must be greater than 0"}
    
    logger.info(f"Attempting to buy {quantity} shares of {symbol}")
    
    # Check account balance first
    account_info = trading_client.get_account()
    if account_info["status"] == "error":
        logger.error(f"Account info error: {account_info['message']}")
        return {"status": "error", "message": f"Could not fetch account info: {account_info['message']}"}
    
    try:
        buying_power = float(account_info["data"]["buying_power"])
        logger.info(f"Current buying power: ${buying_power:.2f}")
        if buying_power < 100:  # Basic check
            return {"status": "error", "message": f"Insufficient buying power: ${buying_power:.2f}"}
    except (KeyError, ValueError) as e:
        logger.error(f"Error parsing buying power: {e}")
        return {"status": "error", "message": "Could not verify buying power"}
    
    result = trading_client.place_order(symbol, quantity, "buy")
    logger.info(f"Buy order result: {result}")
    return result

def sell_stock(symbol: str, quantity: int) -> dict:
    """Sell stocks with specified quantity"""
    global trading_client
    
    if not trading_client:
        logger.error("Trading client not available in sell_stock function")
        return {"status": "error", "message": "Trading client not available"}
    
    if quantity <= 0:
        return {"status": "error", "message": "Quantity must be greater than 0"}
    
    logger.info(f"Attempting to sell {quantity} shares of {symbol}")
    
    result = trading_client.place_order(symbol, quantity, "sell")
    logger.info(f"Sell order result: {result}")
    return result

def get_trading_account_info() -> dict:
    """Get account balance and information"""
    global trading_client
    
    if not trading_client:
        logger.error("Trading client not available in get_trading_account_info function")
        return {"status": "error", "message": "Trading client not available"}
    
    result = trading_client.get_account()
    if result["status"] == "success":
        try:
            data = result["data"]
            formatted_info = {
                "cash": f"${float(data['cash']):.2f}",
                "buying_power": f"${float(data['buying_power']):.2f}",
                "portfolio_value": f"${float(data['portfolio_value']):.2f}",
                "equity": f"${float(data['equity']):.2f}",
                "account_status": data.get('status', 'unknown')
            }
            return {"status": "success", "data": formatted_info}
        except (KeyError, ValueError) as e:
            logger.error(f"Error formatting account data: {e}")
            return {"status": "error", "message": "Error processing account data"}
    return result

def get_trading_portfolio() -> dict:
    """Get current positions"""
    global trading_client
    
    if not trading_client:
        logger.error("Trading client not available in get_trading_portfolio function")
        return {"status": "error", "message": "Trading client not available"}
    
    result = trading_client.get_positions()
    if result["status"] == "success":
        positions = result["data"]
        if not positions:
            return {"status": "success", "message": "No positions found"}
        
        try:
            formatted_positions = []
            for pos in positions:
                formatted_positions.append({
                    "symbol": pos["symbol"],
                    "quantity": pos["qty"],
                    "market_value": f"${float(pos['market_value']):.2f}",
                    "unrealized_pl": f"${float(pos['unrealized_pl']):.2f}",
                    "avg_entry_price": f"${float(pos['avg_entry_price']):.2f}"
                })
            return {"status": "success", "data": formatted_positions}
        except (KeyError, ValueError) as e:
            logger.error(f"Error formatting positions data: {e}")
            return {"status": "error", "message": "Error processing positions data"}
    return result

def get_trading_order_history() -> dict:
    """Get recent orders"""
    global trading_client
    
    if not trading_client:
        logger.error("Trading client not available in get_trading_order_history function")
        return {"status": "error", "message": "Trading client not available"}
    
    result = trading_client.get_orders()
    if result["status"] == "success":
        orders = result["data"]
        if not orders:
            return {"status": "success", "message": "No orders found"}
        
        try:
            formatted_orders = []
            for order in orders[:10]:  # Show last 10 orders
                formatted_orders.append({
                    "id": order["id"],
                    "symbol": order["symbol"],
                    "side": order["side"],
                    "quantity": order["qty"],
                    "status": order["status"],
                    "created_at": order["created_at"][:19]  # Remove milliseconds
                })
            return {"status": "success", "data": formatted_orders}
        except (KeyError, ValueError) as e:
            logger.error(f"Error formatting orders data: {e}")
            return {"status": "error", "message": "Error processing orders data"}
    return result

def parse_trading_command(message: str) -> dict:
    """Parse trading commands from user message"""
    message = message.lower().strip()
    
    # Buy patterns
    buy_patterns = [
        r'buy (\d+) (?:shares of )?([a-zA-Z]+)',
        r'purchase (\d+) (?:shares of )?([a-zA-Z]+)',
        r'get (\d+) (?:shares of )?([a-zA-Z]+)'
    ]
    
    # Sell patterns
    sell_patterns = [
        r'sell (\d+) (?:shares of )?([a-zA-Z]+)',
        r'dispose (\d+) (?:shares of )?([a-zA-Z]+)'
    ]
    
    # Check buy patterns
    for pattern in buy_patterns:
        match = re.search(pattern, message)
        if match:
            return {
                "action": "buy",
                "quantity": int(match.group(1)),
                "symbol": match.group(2).upper()
            }
    
    # Check sell patterns
    for pattern in sell_patterns:
        match = re.search(pattern, message)
        if match:
            return {
                "action": "sell",
                "quantity": int(match.group(1)),
                "symbol": match.group(2).upper()
            }
    
    # Check for account info requests
    if any(word in message for word in ["trading account", "trading balance", "account balance"]):
        return {"action": "trading_account_info"}
    
    # Check for portfolio requests
    if any(word in message for word in ["trading portfolio", "my positions", "holdings"]):
        return {"action": "trading_portfolio"}
    
    # Check for order history
    if any(word in message for word in ["trading orders", "order history", "my trades"]):
        return {"action": "trading_order_history"}
    
    return {"action": "unknown"}

def handle_trading_request(message: str) -> str:
    """Handle trading-related requests"""
    global trading_client
    
    logger.info(f"Handling trading request: {message}")
    logger.info(f"Trading client available: {trading_client is not None}")
    
    if not trading_client:
        logger.error("Trading client not available in handle_trading_request")
        return "❌ Trading service is currently unavailable. Please check your API configuration."
    
    command = parse_trading_command(message)
    logger.info(f"Parsed command: {command}")
    
    if command["action"] == "buy":
        result = buy_stock(command["symbol"], command["quantity"])
        if result["status"] == "success":
            order_data = result["data"]
            return f"✅ Buy order placed successfully!\n" \
                   f"Symbol: {order_data['symbol']}\n" \
                   f"Quantity: {order_data['qty']}\n" \
                   f"Order ID: {order_data['id']}\n" \
                   f"Status: {order_data['status']}"
        else:
            return f"❌ Failed to place buy order: {result['message']}"
    
    elif command["action"] == "sell":
        result = sell_stock(command["symbol"], command["quantity"])
        if result["status"] == "success":
            order_data = result["data"]
            return f"✅ Sell order placed successfully!\n" \
                   f"Symbol: {order_data['symbol']}\n" \
                   f"Quantity: {order_data['qty']}\n" \
                   f"Order ID: {order_data['id']}\n" \
                   f"Status: {order_data['status']}"
        else:
            return f"❌ Failed to place sell order: {result['message']}"
    
    elif command["action"] == "trading_account_info":
        result = get_trading_account_info()
        if result["status"] == "success":
            data = result["data"]
            return f"💰 Trading Account Information:\n" \
                   f"Cash: {data['cash']}\n" \
                   f"Buying Power: {data['buying_power']}\n" \
                   f"Portfolio Value: {data['portfolio_value']}\n" \
                   f"Equity: {data['equity']}\n" \
                   f"Account Status: {data['account_status']}"
        else:
            return f"❌ Could not fetch trading account info: {result['message']}"
    
    elif command["action"] == "trading_portfolio":
        result = get_trading_portfolio()
        if result["status"] == "success":
            if "message" in result:
                return "📊 Your trading portfolio is empty."
            
            positions_text = "📊 Your Trading Portfolio:\n\n"
            for pos in result["data"]:
                positions_text += f"• {pos['symbol']}: {pos['quantity']} shares\n" \
                                f"  Market Value: {pos['market_value']}\n" \
                                f"  Avg Entry: {pos['avg_entry_price']}\n" \
                                f"  P&L: {pos['unrealized_pl']}\n\n"
            return positions_text
        else:
            return f"❌ Could not fetch trading portfolio: {result['message']}"
    
    elif command["action"] == "trading_order_history":
        result = get_trading_order_history()
        if result["status"] == "success":
            if "message" in result:
                return "📋 No recent trading orders found."
            
            orders_text = "📋 Recent Trading Orders:\n\n"
            for order in result["data"]:
                orders_text += f"• {order['side'].upper()} {order['quantity']} {order['symbol']}\n" \
                             f"  Status: {order['status']}\n" \
                             f"  Time: {order['created_at']}\n" \
                             f"  Order ID: {order['id'][:8]}...\n\n"
            return orders_text
        else:
            return f"❌ Could not fetch trading order history: {result['message']}"
    
    else:
        return "❓ I didn't understand that trading command. Try:\n" \
               "• 'buy 10 AAPL'\n" \
               "• 'sell 5 TSLA'\n" \
               "• 'trading account'\n" \
               "• 'trading portfolio'\n" \
               "• 'trading orders'"

def test_alpaca_connection():
    """Test Alpaca API connection and account status"""
    if not trading_client:
        logger.error("❌ Trading client not initialized")
        logger.error("Please check your Alpaca API configuration:")
        logger.error("1. Ensure ALPACA_API_KEY is set in your environment")
        logger.error("2. Ensure ALPACA_SECRET_KEY is set in your environment") 
        logger.error("3. Check that your API keys are valid")
        logger.error("4. Verify your Alpaca account is active")
        return False
    
    try:
        result = trading_client.get_account()
        if result["status"] == "success":
            account_data = result["data"]
            logger.info(f"✅ Account connected successfully")
            logger.info(f"Account Status: {account_data.get('status', 'unknown')}")
            logger.info(f"Trading Blocked: {account_data.get('trading_blocked', 'unknown')}")
            logger.info(f"Account Blocked: {account_data.get('account_blocked', 'unknown')}")
            logger.info(f"Cash: ${account_data.get('cash', '0')}")
            return True
        else:
            logger.error(f"❌ Connection failed: {result}")
            return False
    except Exception as e:
        logger.error(f"❌ Connection test failed: {e}")
        return False

def check_account_status_and_restrictions():
    """Comprehensive check of account status, trading restrictions, and blocks"""
    if not trading_client:
        return {"status": "error", "message": "Trading client not available"}
    
    try:
        result = trading_client.get_account()
        
        if result["status"] == "error":
            return {"status": "error", "message": f"API Error: {result['message']}"}
        
        account_data = result["data"]
        
        # Check 1: Account Status
        account_status = account_data.get("status", "UNKNOWN")
        status_ok = account_status == "ACTIVE"
        
        # Check 2: Trading Enabled (no trading blocks)
        trading_blocked = account_data.get("trading_blocked", True)
        account_blocked = account_data.get("account_blocked", True)
        transfers_blocked = account_data.get("transfers_blocked", True)
        trade_suspended = account_data.get("trade_suspended_by_user", True)
        
        trading_enabled = not trading_blocked and not account_blocked
        
        # Check 3: No restrictions or blocks
        no_restrictions = not trading_blocked and not account_blocked and not transfers_blocked and not trade_suspended
        
        # Additional checks
        pattern_day_trader = account_data.get("pattern_day_trader", False)
        shorting_enabled = account_data.get("shorting_enabled", False)
        
        # Summary
        all_checks_passed = status_ok and trading_enabled and no_restrictions
        
        return {
            "status": "success",
            "all_checks_passed": all_checks_passed,
            "details": {
                "account_status": {
                    "value": account_status,
                    "is_active": status_ok,
                    "message": "✅ Account is ACTIVE" if status_ok else f"❌ Account status is {account_status}"
                },
                "trading_enabled": {
                    "value": not trading_blocked,
                    "check_passed": not trading_blocked,
                    "message": "✅ Trading enabled" if not trading_blocked else "❌ Trading is blocked"
                },
                "restrictions_and_blocks": {
                    "trading_blocked": trading_blocked,
                    "account_blocked": account_blocked, 
                    "transfers_blocked": transfers_blocked,
                    "trade_suspended_by_user": trade_suspended,
                    "no_restrictions": no_restrictions,
                    "message": "✅ No restrictions or blocks" if no_restrictions else "❌ Account has restrictions or blocks"
                },
                "additional_info": {
                    "pattern_day_trader": pattern_day_trader,
                    "shorting_enabled": shorting_enabled,
                    "cash": f"${float(account_data.get('cash', 0)):.2f}",
                    "buying_power": f"${float(account_data.get('buying_power', 0)):.2f}"
                }
            }
        }
        
    except Exception as e:
        return {"status": "error", "message": f"Exception: {str(e)}"}

def print_account_health_check():
    """Print a formatted account health check"""
    result = check_account_status_and_restrictions()
    
    if result["status"] == "error":
        logger.info(f"❌ Account check failed: {result['message']}")
        return
    
    logger.info("=" * 60)
    logger.info("🔍 ALPACA ACCOUNT HEALTH CHECK")
    logger.info("=" * 60)
    
    details = result["details"]
    
    logger.info(f"Overall Status: {'✅ PASSED' if result['all_checks_passed'] else '❌ FAILED'}")
    logger.info("")
    
    # Account Status
    logger.info("1. Account Status Check:")
    logger.info(f"   {details['account_status']['message']}")
    logger.info("")
    
    # Trading Enabled
    logger.info("2. Trading Enabled Check:")
    logger.info(f"   {details['trading_enabled']['message']}")
    logger.info("")
    
    # Restrictions and Blocks
    logger.info("3. Restrictions and Blocks Check:")
    logger.info(f"   {details['restrictions_and_blocks']['message']}")
    restrictions = details['restrictions_and_blocks']
    if not restrictions['no_restrictions']:
        logger.info("   Issues found:")
        if restrictions['trading_blocked']:
            logger.info("   - Trading is blocked")
        if restrictions['account_blocked']:
            logger.info("   - Account is blocked")
        if restrictions['transfers_blocked']:
            logger.info("   - Transfers are blocked")
        if restrictions['trade_suspended_by_user']:
            logger.info("   - Trading suspended by user")
    logger.info("")
    
    # Additional Information
    additional = details['additional_info']
    logger.info("Additional Information:")
    logger.info(f"   Cash: {additional['cash']}")
    logger.info(f"   Buying Power: {additional['buying_power']}")
    logger.info(f"   Pattern Day Trader: {'Yes' if additional['pattern_day_trader'] else 'No'}")
    logger.info(f"   Short Selling Enabled: {'Yes' if additional['shorting_enabled'] else 'No'}")
    
    logger.info("=" * 60)

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config.update({
        'SECRET_KEY': os.getenv('JWT_SECRET_KEY', 'dev-secret-change-in-production'),
        'SQLALCHEMY_DATABASE_URI': os.getenv('DATABASE_URL', 'sqlite:///financial_ai.db'),
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY', 'dev-secret-change-in-production'),
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'SESSION_COOKIE_SECURE': False,
        'PERMANENT_SESSION_LIFETIME': timedelta(days=1)
    })
    
    # Initialize extensions
    init_db(app)
    JWTManager(app)
    
    # Create demo user
    with app.app_context():
        demo_user = User.query.filter_by(username='demo').first()
        if not demo_user:
            demo_user = User(
                username='demo',
                password_hash=generate_password_hash('password'),
                phone_number='2222222222'
            )
            db.session.add(demo_user)
            db.session.commit()
            logger.info("✅ Created demo user")
    
    # Test Alpaca connection on startup
    logger.info("\n" + "="*50)
    logger.info("🔍 TESTING ALPACA CONNECTION ON STARTUP")
    logger.info("="*50)
    
    if trading_client_initialized:
        test_alpaca_connection()
        print_account_health_check()
    else:
        logger.error("❌ Cannot test connection - Trading client not initialized")
        logger.error("🔧 Please check the following:")
        logger.error("1. Set ALPACA_API_KEY in your .env file")
        logger.error("2. Set ALPACA_SECRET_KEY in your .env file") 
        logger.error("3. Ensure your .env file is in the correct directory")
        logger.error("4. Restart the application after setting environment variables")
        logger.error("5. Check that your API keys are from Alpaca Paper Trading")
    
    logger.info("="*50 + "\n")
    
    # Server URLs
    FI_MCP_URL = f"http://localhost:{os.getenv('FI_MCP_PORT', '3001')}"
    ADK_URL = f"http://localhost:{os.getenv('ADK_PORT', '8000')}"

    # Helper functions
    async def authenticate_fi_mcp(phone_number: str, otp: str = "123456"):
        """Authenticate with Fi MCP server"""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{FI_MCP_URL}/login",
                    json={"phoneNumber": phone_number, "otp": otp}
                )
                if response.status_code == 200:
                    result = response.json()
                    if result.get("success"):
                        session_cookie = response.cookies.get("fi-mcp-session")
                        return {"success": True, "session_cookie": session_cookie}
                return {"success": False, "message": "Authentication failed"}
        except Exception as e:
            logger.error(f"Fi MCP auth error: {e}")
            return {"success": False, "message": str(e)}
    
    async def call_fi_mcp(endpoint: str, phone_number: str):
        """Call Fi MCP endpoint"""
        try:
            headers = {"X-Phone-Number": phone_number}
            
            # Add session cookie if available
            cookies = {}
            fi_session = session.get('fi_mcp_session')
            if fi_session:
                cookies = {"fi-mcp-session": fi_session}
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{FI_MCP_URL}{endpoint}",
                    headers=headers,
                    cookies=cookies
                )
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.error(f"Fi MCP error: {response.status_code}")
                    return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"Fi MCP call error: {e}")
            return {"error": str(e)}
    
    async def call_adk(query: str, user_context: dict):
        """Call ADK orchestrator"""
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{ADK_URL}/api/chat",
                    json={"message": query, "user_context": user_context}
                )
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.error(f"ADK error: {response.status_code}")
                    return {"error": f"HTTP {response.status_code}", "final_answer": "Sorry, AI service is unavailable."}
        except Exception as e:
            logger.error(f"ADK call error: {e}")
            return {"error": str(e), "final_answer": "Sorry, I couldn't process your request."}
    
    # Routes
    @app.route('/')
    def index():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return render_template('dashboard.html')
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            
            if not username or not password:
                flash('Username and password are required', 'error')
                return render_template('login.html')
            
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                # Authenticate with Fi MCP
                try:
                    auth_result = asyncio.run(authenticate_fi_mcp(user.phone_number))
                    if auth_result.get("success"):
                        session.permanent = True
                        session.update({
                            'user_id': user.id,
                            'username': user.username,
                            'phone_number': user.phone_number,
                            'fi_mcp_session': auth_result.get("session_cookie")
                        })
                        flash('Login successful!', 'success')
                        return redirect(url_for('dashboard'))
                    else:
                        flash(f'Fi MCP authentication failed: {auth_result.get("message")}', 'error')
                except Exception as e:
                    flash(f'Authentication error: {str(e)}', 'error')
            else:
                flash('Invalid username or password', 'error')
        
        return render_template('login.html')
    
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            phone_number = request.form.get('phone_number', '').strip()

            if not username or not password or not phone_number:
                flash('All fields are required.', 'error')
                return redirect(url_for('register'))

            # Check if user already exists
            if User.query.filter_by(username=username).first():
                flash('Username already exists. Please choose another.', 'error')
                return redirect(url_for('register'))

            # Create new user
            user = User(
                username=username,
                phone_number=phone_number,
                password_hash=generate_password_hash(password)
            )
            db.session.add(user)
            db.session.commit()

            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

        return render_template('register.html')
    
    @app.route('/logout')
    def logout():
        session.clear()
        flash('Logged out successfully', 'info')
        return redirect(url_for('login'))
    
    @app.route('/dashboard')
    def dashboard():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return render_template('dashboard.html')
    
    @app.route('/chat')
    def chat():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return render_template('chat.html')
    
    # API Routes
    @app.route('/api/net-worth')
    def api_net_worth():
        if 'user_id' not in session:
            return jsonify({"error": "Not authenticated"}), 401
        
        phone_number = session.get('phone_number')
        if not phone_number:
            return jsonify({"error": "Phone number not found"}), 400
        
        try:
            data = asyncio.run(call_fi_mcp("/api/fetch-net-worth", phone_number))
            
            # Parse Fi MCP response
            if "netWorthResponse" in data:
                nw_response = data["netWorthResponse"]
                assets = {}
                liabilities = {}
                
                # Parse assets
                for asset in nw_response.get("assetValues", []):
                    asset_type = asset["netWorthAttribute"].replace("ASSET_TYPE_", "").lower()
                    value = float(asset["value"]["units"])
                    
                    if "mutual" in asset_type:
                        assets["mutualFunds"] = assets.get("mutualFunds", 0) + value
                    elif "epf" in asset_type:
                        assets["epf"] = assets.get("epf", 0) + value
                    elif "bank" in asset_type:
                        assets["bankBalance"] = assets.get("bankBalance", 0) + value
                    else:
                        assets["stocks"] = assets.get("stocks", 0) + value
                
                # Parse liabilities
                for liability in nw_response.get("liabilityValues", []):
                    liability_type = liability["netWorthAttribute"].replace("LIABILITY_TYPE_", "").lower()
                    value = float(liability["value"]["units"])
                    
                    if "credit" in liability_type:
                        liabilities["creditCard"] = liabilities.get("creditCard", 0) + value
                    else:
                        liabilities["personalLoan"] = liabilities.get("personalLoan", 0) + value
                
                total_net_worth = float(nw_response.get("totalNetWorthValue", {}).get("units", "0"))
                
                return jsonify({
                    "status": "success",
                    "data": {
                        "totalNetWorth": total_net_worth,
                        "assets": assets,
                        "liabilities": liabilities,
                        "changePercent": 1.3  # Mock percentage change
                    }
                })
            
            # Fallback to mock data
            return jsonify({
                "status": "success",
                "data": {
                    "totalNetWorth": 1177531,
                    "assets": {
                        "mutualFunds": 846420,
                        "epf": 211111,
                        "bankBalance": 125000,
                        "stocks": 170000
                    },
                    "liabilities": {
                        "creditCard": 25000,
                        "personalLoan": 150000
                    },
                    "changePercent": 1.3
                }
            })
            
        except Exception as e:
            logger.error(f"Net worth API error: {e}")
            return jsonify({"error": "Failed to fetch net worth data"}), 500
    
    @app.route('/api/chat', methods=['POST'])
    def api_chat():
        if 'user_id' not in session:
            return jsonify({"error": "Not authenticated"}), 401
        
        try:
            data = request.json or {}
            query = data.get('message', '').strip()
            
            if not query:
                return jsonify({"error": "Message is required"}), 400
            
            # Check if it's a trading-related message
            trading_keywords = ["buy", "sell", "trading account", "trading portfolio", "trading orders", "positions", "holdings"]
            if any(keyword in query.lower() for keyword in trading_keywords):
                # Handle trading request directly
                trading_response = handle_trading_request(query)
                
                # Save chat session to database
                try:
                    chat_session = ChatSession(
                        user_id=session['user_id'],
                        query=query,
                        response=trading_response
                    )
                    db.session.add(chat_session)
                    db.session.commit()
                    logger.info(f"✅ Saved trading chat session for user {session['user_id']}")
                except Exception as e:
                    logger.error(f"❌ Error saving trading chat session: {e}")
                
                return jsonify({
                    "final_answer": trading_response,
                    "type": "trading",
                    "status": "success"
                })
            
            # Handle non-trading requests with existing ADK logic
            user_context = {
                "user_id": session['user_id'],
                "phone_number": session.get('phone_number'),
                "username": session.get('username')
            }
            
            # Call ADK orchestrator
            result = asyncio.run(call_adk(query, user_context))
            
            # Save chat session to database
            try:
                chat_session = ChatSession(
                    user_id=session['user_id'],
                    query=query,
                    response=json.dumps(result)
                )
                db.session.add(chat_session)
                db.session.commit()
                logger.info(f"✅ Saved chat session for user {session['user_id']}")
            except Exception as e:
                logger.error(f"❌ Error saving chat session: {e}")
            
            return jsonify(result)
            
        except Exception as e:
            logger.error(f"Chat API error: {e}")
            return jsonify({
                "error": "Chat service unavailable",
                "final_answer": "Sorry, I'm having trouble processing your request right now."
            }), 500

    @app.route('/test-account-health')
    def test_account_health():
        if 'user_id' not in session:
            return jsonify({"error": "Not authenticated"}), 401
    
        result = check_account_status_and_restrictions()
        return jsonify(result)
    
    @app.route('/api/health')
    def api_health():
        health_status = {
            "web_app": "healthy",
            "database": "healthy",
            "alpaca_api": "unknown",
            "timestamp": datetime.now().isoformat()
        }
        
        # Test database connection
        try:
            db.session.execute('SELECT 1')
            health_status["database"] = "healthy"
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            health_status["database"] = "unhealthy"
        
        # Test Alpaca API connection
        if trading_client:
            try:
                result = trading_client.get_account()
                health_status["alpaca_api"] = "healthy" if result["status"] == "success" else "unhealthy"
            except Exception as e:
                logger.error(f"Alpaca API health check failed: {e}")
                health_status["alpaca_api"] = "unhealthy"
        else:
            health_status["alpaca_api"] = "not_configured"
        
        return jsonify(health_status)
    
    @app.route('/api/generate-itr', methods=['POST'])
    def api_generate_itr():
        if 'user_id' not in session:
            return jsonify(error="Not authenticated"), 401
        
        try:
            # Call tax accountant agent
            ctx = {
                "user_id": session['user_id'],
                "phone_number": session['phone_number'],
                "username": session['username']
            }
            
            result = asyncio.run(call_adk("generate my income tax return and optimize tax savings", ctx))
            
            # Extract tax accountant response
            tax_data = None
            for response in result.get('responses', []):
                if response.get('agent') == 'tax_accountant':
                    tax_data = response.get('data', {})
                    break
            
            if not tax_data:
                return jsonify(error="Tax calculation failed"), 500
            
            # Save to database
            tax_return = TaxReturn(
                user_id=session['user_id'],
                assessment_year="2025-26",
                financial_year="2024-25",
                gross_income=tax_data.get('tax_calculation', {}).get('gross_income', 0),
                taxable_income=tax_data.get('tax_calculation', {}).get('taxable_income', 0),
                total_tax_payable=tax_data.get('tax_calculation', {}).get('total_tax_payable', 0),
                itr_json=json.dumps(tax_data.get('itr_json', {})),
                optimization_suggestions=json.dumps(tax_data.get('optimization_suggestions', [])),
                ai_summary=tax_data.get('ai_summary', '')
            )
            
            db.session.add(tax_return)
            db.session.commit()
            
            return jsonify(status="success", data=tax_data)
            
        except Exception as e:
            logger.error(f"ITR generation error: {e}")
            return jsonify(error=str(e)), 500

    @app.route('/api/download-itr-json/<int:tax_return_id>')
    def download_itr_json(tax_return_id):
        if 'user_id' not in session:
            return jsonify(error="Not authenticated"), 401
        
        tax_return = TaxReturn.query.filter_by(
            id=tax_return_id, 
            user_id=session['user_id']
        ).first()
        
        if not tax_return:
            return jsonify(error="Tax return not found"), 404
        
        return jsonify(
            status="success",
            itr_json=json.loads(tax_return.itr_json),
            filename=f"ITR_{tax_return.assessment_year}_{session['username']}.json"
        )

    @app.route('/api/trading/account')
    def api_trading_account():
        if 'user_id' not in session:
            return jsonify({"error": "Not authenticated"}), 401
        
        result = get_trading_account_info()
        return jsonify(result)

    @app.route('/api/trading/portfolio')
    def api_trading_portfolio():
        if 'user_id' not in session:
            return jsonify({"error": "Not authenticated"}), 401
        
        result = get_trading_portfolio()
        return jsonify(result)

    @app.route('/api/trading/orders')
    def api_trading_orders():
        if 'user_id' not in session:
            return jsonify({"error": "Not authenticated"}), 401
        
        result = get_trading_order_history()
        return jsonify(result)

    @app.route('/api/trading/buy', methods=['POST'])
    def api_trading_buy():
        if 'user_id' not in session:
            return jsonify({"error": "Not authenticated"}), 401
        
        data = request.json or {}
        symbol = data.get('symbol', '').strip().upper()
        quantity = data.get('quantity', 0)
        
        if not symbol or quantity <= 0:
            return jsonify({"error": "Valid symbol and quantity required"}), 400
        
        result = buy_stock(symbol, quantity)
        return jsonify(result)

    @app.route('/api/trading/sell', methods=['POST'])
    def api_trading_sell():
        if 'user_id' not in session:
            return jsonify({"error": "Not authenticated"}), 401
        
        data = request.json or {}
        symbol = data.get('symbol', '').strip().upper()
        quantity = data.get('quantity', 0)
        
        if not symbol or quantity <= 0:
            return jsonify({"error": "Valid symbol and quantity required"}), 400
        
        result = sell_stock(symbol, quantity)
        return jsonify(result)

    @app.route('/api/trading/cancel-order', methods=['POST'])
    def api_trading_cancel_order():
        if 'user_id' not in session:
            return jsonify({"error": "Not authenticated"}), 401
        
        data = request.json or {}
        order_id = data.get('order_id', '').strip()
        
        if not order_id:
            return jsonify({"error": "Order ID is required"}), 400
        
        if not trading_client:
            return jsonify({"error": "Trading client not available"}), 500
        
        result = trading_client.cancel_order(order_id)
        return jsonify(result)
    
    @app.route('/api/trading/market-data/<symbol>')
    def api_trading_market_data(symbol):
        if 'user_id' not in session:
            return jsonify({"error": "Not authenticated"}), 401
        
        if not symbol:
            return jsonify({"error": "Symbol is required"}), 400
        
        if not trading_client:
            return jsonify({"error": "Trading client not available"}), 500
        
        result = trading_client.get_market_data(symbol.upper())
        return jsonify(result)

    # Debug route for testing Alpaca API
    @app.route('/debug/alpaca-test')
    def debug_alpaca_test():
        if 'user_id' not in session:
            return jsonify({"error": "Not authenticated"}), 401
        
        debug_info = {
            "client_initialized": trading_client is not None,
            "api_key_present": bool(os.getenv("ALPACA_API_KEY")),
            "secret_key_present": bool(os.getenv("ALPACA_SECRET_KEY")),
            "api_key_prefix": os.getenv("ALPACA_API_KEY", "")[:8] + "..." if os.getenv("ALPACA_API_KEY") else None,
            "base_url": trading_client.base_url if trading_client else None,
            "headers_sample": {
                "APCA-API-KEY-ID": trading_client.headers.get("APCA-API-KEY-ID", "")[:8] + "..." if trading_client else None,
                "Content-Type": trading_client.headers.get("Content-Type") if trading_client else None
            } if trading_client else None,
            "initialization_status": trading_client_initialized
        }
        
        if trading_client:
            # Test account endpoint
            account_result = trading_client.get_account()
            debug_info["account_test"] = account_result
        else:
            debug_info["error_message"] = "Trading client not initialized. Check your environment variables."
        
        return jsonify(debug_info)

    # Environment check route
    @app.route('/debug/env-check')
    def debug_env_check():
        if 'user_id' not in session:
            return jsonify({"error": "Not authenticated"}), 401
        
        env_info = {
            "ALPACA_API_KEY": {
                "present": bool(os.getenv("ALPACA_API_KEY")),
                "length": len(os.getenv("ALPACA_API_KEY", "")),
                "prefix": os.getenv("ALPACA_API_KEY", "")[:8] + "..." if os.getenv("ALPACA_API_KEY") else None
            },
            "ALPACA_SECRET_KEY": {
                "present": bool(os.getenv("ALPACA_SECRET_KEY")),
                "length": len(os.getenv("ALPACA_SECRET_KEY", "")),
                "prefix": os.getenv("ALPACA_SECRET_KEY", "")[:8] + "..." if os.getenv("ALPACA_SECRET_KEY") else None
            },
            "dotenv_loaded": True,  # Since we call load_dotenv()
            "current_dir": os.getcwd(),
            "env_file_exists": os.path.exists(".env")
        }
        
        return jsonify(env_info)
    
    return app

if __name__ == "__main__":
    app = create_app()
    port = int(os.getenv("WEB_APP_PORT", "5000"))
    logger.info(f"🌐 Starting Financial AI Platform Web App on port {port}")
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")