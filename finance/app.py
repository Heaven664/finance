import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Configuring datetime
now = datetime.now()

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Symbols and numbers of shares from database
    shares = db.execute(
        "SELECT symbol, number FROM shares JOIN users ON users.username = shares.owner WHERE users.id = ?", session["user_id"])

    # User's balance
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0].get('cash')

    # User's balance with active shares
    big_total = cash

    # Iterating through every share in portfolio
    for share in shares:

        # Returns dictionary with symbol, price and name of a share
        info = lookup(share["symbol"])

        # Multiplying number of a share on its price
        total = info["price"] * share["number"]

        # Formatting share's total to show only 2 decimal digits
        format_total = total

        # Adds total of every share to users balance
        big_total += total

        # Add's total to a dictionary
        info["total"] = format_total

        # Concatenates two dictionaries
        share.update(info)

    # Renders a homepage template
    return render_template("index.html", shares=shares, total=big_total, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    # User reached the route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Symbol is not provided
        if not request.form.get("symbol"):
            return apology("You forgot symbol")

        # Symbol is not provided
        if not request.form.get("shares").isdigit():
            return apology("You forgot shares")

        # Gets symbol from users input
        symbol = request.form.get("symbol").upper()

        # Gets number from users input
        number = int(request.form.get("shares"))

        # Checks the share
        share_info = lookup(symbol)

        # Checks if inputted symbol exists
        if not share_info:
            return apology("You forgot shares")

        # Formatted price
        format_price = share_info.get("price")

        # Number of shares less then 1
        if number <= 0:
            return apology("You can not buy less then 1 share")

        # Symbol doesn't exists
        elif not share_info:
            return apology("Symbol does not exist")

        # Price of shares users buys
        amount = share_info["price"] * number

        # Info about buyer's from database
        buyer_info = db.execute("SELECT * FROM users WHERE id= ? ", session["user_id"])

        # Buyer's balance before the transaction
        buyer_cash = buyer_info[0]['cash']

        # Buyer's username
        buyer_name = buyer_info[0]['username']

        # Buyer does not have enough money
        if buyer_cash < amount:
            return apology("You do not have enough money to buy this share")

        # Action of the transaction
        action = 'bought'

        # Updated buyer's balance after the transaction
        new_cash = buyer_cash - amount

        # Current datetime in format DD-MM-YYYY HH:MM:SS
        date = now.strftime("%d/%m/%Y %H:%M:%S")

        # Updates buyer's balance
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, session["user_id"])

        # Adds information about transaction into database
        db.execute("INSERT INTO history (user, number, symbol, action, date, price) VALUES (?, ?, ?, ?, ?, ?)",
                   buyer_name, number, symbol, action, date, format_price)

        # Returns dictionary from buyers portfolio with the same symbol
        share = db.execute("SELECT symbol FROM shares WHERE symbol = ?", symbol)

        # Buyer already has this share
        if not share:
            db.execute("INSERT INTO shares (owner, number, symbol) VALUES (?, ?, ?)",
                       buyer_name, number, symbol)

        # Buyer does not have this share yet
        else:

            # Gets number of shares in user's portfolio with the specific symbol)
            share_amount = db.execute("SELECT number FROM shares WHERE symbol = ?", symbol)

            # Adds old number to number of shares user have bought
            new_amount = share_amount[0]["number"] + number

            # Updates portfolio
            db.execute("UPDATE shares SET number = ? WHERE symbol = ?", new_amount, symbol)

        # Redirects to homepage
        return redirect("/")

    # User reached route via GET (as by clicking on the link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute(
        "SELECT * FROM history JOIN users ON users.username = history.user WHERE users.id = ? ORDER BY date DESC", session["user_id"])

    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # User reached the route via POST (as by submitting form via POST)
    if request.method == "POST":

        # Symbol from user's input
        symbol = request.form.get("symbol")

        # Dictionary with name, price and symbol
        info = lookup(symbol)

        # If dictionary is empty
        if not info:
            return apology("Invalid Symbol", 400)

        # Renders a template with info about a share
        return render_template("quoted.html",  info=info)

    # User reached route via GET (as by following a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Username from input
        username = request.form.get("username")

        # Password from input
        password = request.form.get("password")

        # Confirmation password from input
        confirmation = request.form.get("confirmation")

        # Checks if username exist in database
        users = db.execute("SELECT id FROM users WHERE username = ?", username)

        # If username is not provided
        if not username:
            return apology("Please input your username", 400)

        # If username exists in database
        elif len(users) != 0:
            return apology("This username already exists", 400)

        # If password is not provided
        elif not password:
            return apology("Please input your password", 400)

        # If confirmation password is not provided
        elif not confirmation:
            return apology("Please confirm your password", 400)

        # If confirmation password doesn't match
        elif password != confirmation:
            return apology("You confirmed your password incorrectly", 400)

        # Hashes user's password
        hashed_password = generate_password_hash(password)

        # Inserts user's password into database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)

        # Redirects to main page
        return redirect("/")

    # If user reached rout via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User reached route via POST (as by submitting a form of via redirect)
    if request.method == "POST":

        # Symbol is not provided
        if not request.form.get("symbol"):
            return apology("Forgot to choose a share", 403)

        # Amount is not provided
        if not request.form.get("shares").isdigit():
            return apology("Please input number of shares")

        # Info about seller from database
        user_info = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Symbol of the share to be sold
        symbol = request.form.get("symbol").upper()

        # Amount of the shares to be sold
        amount = int(request.form.get("shares"))

        # If user inputted number of shares less than 1
        if amount < 1:
            return apology("Number of shares must be at least 1", 403)

        # Transaction name
        action = 'sold'

        # Returns a dictionary with price, name and symbol of the share
        share_info = lookup(symbol)

        # If symbol is not valid
        if not share_info:
            return apology("Symbol doesn't exist")

        # Actual amount of a share from user's portfolio
        actual_amount = db.execute("SELECT number FROM shares WHERE symbol = ?", symbol)

        # If user doesn't have this share
        if not actual_amount:
            return apology("You do not have this share")

        # If user's number of the share is less than amount of shares that he wants to sell
        elif actual_amount[0].get('number') < amount:
            return apology("Not enough shares")

        # Current price of the share
        share_price = share_info["price"]

        # Amount to be deposited in sellers balance
        price_total = share_info["price"] * amount

        # Current datetime in format DD-MM-YYYY HH:MM:SS
        date = now.strftime("%d/%m/%Y %H:%M:%S")

        # Seller's balance after transaction
        new_balance = user_info[0]["cash"] + price_total

        # Number of the share left in user's portfolio after transaction
        new_number = db.execute("SELECT number FROM shares JOIN users ON users.username = shares.owner WHERE users.id = ? AND symbol= ? ",
                                session["user_id"], symbol)[0].get('number') - amount

        # Updates balance after transaction
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_balance, session["user_id"])

        # Updates portfolio after transaction
        db.execute("UPDATE shares SET number = ? WHERE owner = ? AND symbol = ?", new_number,  user_info[0].get('username'), symbol)

        # Updates history after transaction
        db.execute("INSERT INTO history (user, number, symbol, action, date, price) VALUES(?, ?, ?, ?, ?, ?)",
                   user_info[0].get('username'), amount, symbol, action, date, share_price)

        # Removes all shares from portfolio which number is zero
        db.execute("DELETE FROM shares WHERE number IS 0")

        # Redirects to homepage
        return redirect("/")

    # User reached route via GET (as by clicking on a link or via redirect)
    else:

        # Gets symbols of shares in user's portfolio
        portfolio_info = db.execute(
            "SELECT symbol FROM shares JOIN users ON users.username = shares.owner WHERE users.id = ? ", session["user_id"])

        # Renders a template with selling options
        return render_template("sell.html", portfolio=portfolio_info)