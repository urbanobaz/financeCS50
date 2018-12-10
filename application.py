import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash


from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():

    user_id = session["user_id"]

    transactions = db.execute(
        "SELECT symbol, shares, price, name FROM transactions WHERE user_id = :user_id", user_id=session["user_id"])
    portfolio = db.execute("SELECT symbol, shares, price, name FROM portfolio WHERE user_id = :user_id", user_id=session["user_id"])

    rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])

    remCash = rows[0]["cash"]
    totalValue = 0

    for transaction in portfolio:
        totalValue = (totalValue + (transaction["price"] * transaction["shares"]))

    return render_template("index.html", transactions=portfolio, remCash=remCash, totalValue=totalValue)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        stock = lookup(request.form.get("symbol"))

        if not stock:
            return apology("Invalid ticker!")

        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Enter a number")

        if shares < 0:
            return apology("Shares need to be a positive number")

        rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])

        remCash = rows[0]["cash"]

        price = stock["price"]
        symbol = stock["symbol"]
        name = stock["name"]

        totPrice = shares * price

        if remCash < totPrice:
            return apology("Insufficient funds")

        db.execute("UPDATE users SET cash = cash - :totPrice WHERE id = :user_id", totPrice=totPrice, user_id=session["user_id"])
        db.execute("INSERT INTO 'transactions' (user_id, symbol, shares, price, name) VALUES (:user_id, :symbol, :shares, :price, :name)",
                   user_id=session["user_id"], symbol=symbol, shares=shares, price=price, name=name)

        portfolio = db.execute("SELECT symbol, SUM(shares) as amount_of_shares FROM portfolio WHERE symbol=:symbol AND user_id=:user_id",
                               user_id=session["user_id"], symbol=symbol)

        if portfolio[0]["symbol"] == symbol:
            db.execute("UPDATE portfolio SET shares = shares + :shares WHERE symbol = :symbol AND user_id = :user_id ", user_id=session["user_id"],
                       symbol=symbol, shares=shares)
        else:
            db.execute("INSERT INTO portfolio (user_id, symbol, shares, price, name) VALUES (:user_id, :symbol, :shares, :price, :name)",
                       user_id=session["user_id"], symbol=symbol, shares=shares, price=price, name=name)

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT symbol, shares, price, timestamp FROM transactions WHERE user_id = :user_id", user_id=session["user_id"])
    return render_template("history.html", transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
    # if request method is post
    if request.method == "POST":
        symbol = request.form.get("symbol")

        info = lookup(symbol)
        if not info:
            return apology("Invalid ticker")

        name = info.get('name')
        price = info.get('price')

        return render_template("quoted.html", symbol=symbol, name=name, price=price)

    # if request method is get
    if request.method == "GET":
        return render_template("quote.html")
    # return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    # if request method is post
    if request.method == "POST":

        if not request.form.get("username"):
            return apology("Must provide username")

        elif not request.form.get("password") or not request.form.get("confirmation"):
            return apology("Must provide passwords")

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # making sure passwords from html forms match, returning apology function if they don't
        if password != confirmation:
            return apology("Passwords don't match!")

        # hashing password
        password = generate_password_hash(request.form.get("password"))

        # checking for inputted username in register form
        results = db.execute("SELECT * FROM users WHERE username=:username", username=username)

        # returning apology function if results returned data
        if results:
            return apology("Username already exists", 400)
        else:
            new = db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)",
                             username=username, password=password)
            return apology("Registration complete", 200)

        # inserting username and password if username didn't already exist
        # new = db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)", username=username, password=password)

        session["user_id"] = results

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    transactions = db.execute(
        "SELECT symbol, SUM(shares) as amount_of_shares FROM transactions WHERE user_id = :user_id GROUP BY symbol", user_id=session["user_id"])
    portfolio = db.execute(
        "SELECT symbol, SUM(shares) as amount_of_shares FROM portfolio WHERE user_id = :user_id GROUP BY symbol", user_id=session["user_id"])

    if request.method == "POST":

        stock = lookup(request.form.get("symbol"))

        if not stock:
            return apology("Invalid ticker")

        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Must be a number")

        if shares < 0:
            return apology("Shares must be a positive number")

        if transactions[0]["amount_of_shares"] < 1 or shares > transactions[0]["amount_of_shares"]:
            return apology("Not enough shares")

        price = stock["price"]
        symbol = stock["symbol"]
        name = stock["name"]
        total_price = price * shares

        db.execute("UPDATE users SET cash = cash + :total_price WHERE id = :user_id",
                   total_price=total_price, user_id=session["user_id"])
        db.execute("INSERT INTO 'transactions' (user_id, symbol, shares, price, name) VALUES (:user_id, :symbol, :shares, :price, :name)",
                   user_id=session["user_id"], symbol=symbol, shares=(shares * -1), price=price, name=name)

        portfolio = db.execute("SELECT symbol, SUM(shares) as amount_of_shares FROM portfolio WHERE symbol=:symbol AND user_id=:user_id",
                               user_id=session["user_id"], symbol=symbol)

        if (portfolio[0]["symbol"] == symbol) and (portfolio[0]["amount_of_shares"] != shares):
            db.execute("UPDATE portfolio SET shares = shares - :shares WHERE symbol = :symbol AND user_id = :user_id ",
                       user_id=session["user_id"], symbol=symbol, shares=shares)
        elif portfolio[0]["amount_of_shares"] == shares:
            db.execute("DELETE FROM portfolio WHERE symbol = :symbol AND user_id = :user_id",
                       user_id=session["user_id"], symbol=symbol)

        return redirect("/")
    else:
        return render_template("sell.html", transactions=portfolio)
    # return apology("TODO")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
