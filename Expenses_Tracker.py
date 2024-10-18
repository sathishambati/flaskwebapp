

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import pyodbc
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta,datetime,date
from flask_cors import CORS
 
app = Flask(__name__)

CORS(app)
 
# SQL Server connection string using SQLAlchemy with pyodbc driver
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://satish:1234@DESKTOP-AD8EJ9D\\SQLEXPRESS/Expense_Tracker?driver=ODBC+Driver+17+for+SQL+Server'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
 
# JWT Configuration
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this to a random secret
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
 
jwt = JWTManager(app)
 
db = SQLAlchemy(app)
 
# Define the User model (for authentication)
class Users(db.Model):
    __tablename__ = 'Users'
    UserID = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(80), unique=True, nullable=False)
    Password = db.Column(db.String(200), nullable=False)
    # Expenses = db.relationship('Expenses', backref='Users', lazy=True)
 
# Define the Product model
class Expenses(db.Model):
    __tablename__ = 'Expenses'
    ExpenseID = db.Column(db.Integer, primary_key=True)
    ExpenseName = db.Column(db.String(100), nullable=False)
    ExpenseType = db.Column(db.String(50), nullable=False)
    Amount = db.Column(db.Numeric(10, 2), nullable=False)
    ExpenseDAte = db.Column(db.Date, default=datetime.now())
    UserID = db.Column(db.Integer, db.ForeignKey('Users.UserID'),
        nullable=False)

# 1. User Registration
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='scrypt')

    new_user = Users(Username=data['username'], Password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


 
# 2. User Login (JWT token generation)
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    user = Users.query.filter_by(Username=data['username']).first()

    if not user or not check_password_hash(user.Password, data['password']):
        return jsonify({'message': 'Invalid username or password'}), 401

    # Create JWT Token
    access_token = create_access_token(identity=user.UserID)
    return jsonify(access_token=access_token)

 
 
# 3. Create a new expense
@app.route('/expense', methods=['POST'])
@jwt_required()
def create_Expense():
    current_user = get_jwt_identity()  # Get the username of the logged-in user
 
    data = request.get_json()
    new_expense = Expenses(
        UserID = get_jwt_identity(),
        ExpenseName=data['ExpenseName'],
        ExpenseType=data['ExpenseType'],
        Amount=data['Amount']
        
    )
    db.session.add(new_expense)
    db.session.commit()
    return jsonify({'message': 'Product created successfully'}), 201
 
# 4. Get all expenses (Public Route)
@app.route('/expenses', methods=['GET'])
def get_expenses():
    expenses = Expenses.query.all()
    output = []
    for expense in expenses:
        expense_data = {
            'ExpenseID': expense.ExpenseID,
            'ExpenseName': expense.ExpenseName,
            'ExpenseType': expense.ExpenseType,
            'Amount': str(expense.Amount),
            'UserID': expense.UserID
        }
        output.append(expense_data)
    return jsonify({'expenses': output})
 
# 5. Get a single expenses by ID (Protected Route)
@app.route('/expenses/<int:id>', methods=['GET'])
@jwt_required()
def get_expense(id):
    userid = get_jwt_identity()
   
    expense = db.session.query(Expenses).filter_by(ExpenseID=id, UserID=userid).first()
    
    if not expense:
        return jsonify({'message': 'Invalid id'}), 404
    
    data = request.get_json()
    expense_data = {
        'ExpenseID': expense.ExpenseID,
        'ExpenseName': expense.ExpenseName,
        'ExpenseType': expense.ExpenseType,
        'Amount': str(expense.Amount),
        'UserID' : expense.UserID
    }
    return jsonify(expense_data)


#6.search by date range
@app.route('/expenses/daterange', methods=['GET'])
@jwt_required()
def get_expenses_daterange():
    data = request.get_json()

    st = data['start_date'].split('-')
    ed = data['end_date'].split('-')
    start_date = date(int(st[2]), int(st[1]), int(st[0]))
    end_date = date(int(ed[2]), int(ed[1]), int(ed[0]))

    query = text("""
    SELECT * 
    FROM Expenses 
    WHERE ExpenseDate BETWEEN :start_date AND :end_date 
    AND UserID = :userid
""")
    
    # Execute the query with the provided category
    userid = get_jwt_identity()
    result = db.session.execute(query, {'start_date': start_date,'end_date':end_date,'userid':userid})
    
    expenses = result.fetchall()
    if not expenses:
        return jsonify({'message': 'Invalid category'}), 404
    output = []
    for expense in expenses:
        expense_data = {
            'ExpenseID': expense.ExpenseID,
            'ExpenseName': expense.ExpenseName,
            'ExpenseType': expense.ExpenseType,
            'Amount': str(expense.Amount),
            'UserID': expense.UserID
        }
        output.append(expense_data)
    return jsonify({'expenses': output})


#7.search by category
@app.route('/expenses/<string:category>', methods=['GET'])
@jwt_required()
def get_expenses_category(category):

    query = text("SELECT * FROM Expenses WHERE ExpenseType = :category and UserID = :userid")
    
    # Execute the query with the provided category
    userid = get_jwt_identity()
    result = db.session.execute(query, {'category': category,'userid':userid})
    
    expenses = result.fetchall()
    if not expenses:
        return jsonify({'message': 'Invalid category'}), 404
    output = []
    for expense in expenses:
        expense_data = {
            'ExpenseID': expense.ExpenseID,
            'ExpenseName': expense.ExpenseName,
            'ExpenseType': expense.ExpenseType,
            'Amount': str(expense.Amount),
            'UserID': expense.UserID
        }
        output.append(expense_data)
    return jsonify({'expenses': output})
 
# 8. Update a expenses by ID (Protected Route)
@app.route('/expenses/<int:id>', methods=['PUT'])
@jwt_required()
def update_expense(id):
    userid = get_jwt_identity()
   
    expense = db.session.query(Expenses).filter_by(ExpenseID=id, UserID=userid).first()
    
    if not expense:
        return jsonify({'message': 'Invalid id'}), 404
    
    data = request.get_json()
    
    expense.ExpenseName = data.get('ExpenseName', expense.ExpenseName)
    expense.ExpenseType = data.get('ExpenseType', expense.ExpenseType)
    expense.Amount = data.get('Amount', expense.Amount)


    db.session.commit()
   
    return jsonify({'message': 'Expense updated successfully'})


 
# 9. Delete a expenses by ID (Protected Route)
@app.route('/expenses/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_expense(id):
    query = text("""
    SELECT * 
    FROM Expenses 
    WHERE ExpenseID = :id
    AND UserID = :userid
    """)
    
    userid = get_jwt_identity()
    result = db.session.execute(query, {'id': id, 'userid': userid})  # Use 'id' as the key

    expenses = result.fetchall()
    if not expenses:
        return jsonify({'message': 'Invalid id'}), 404
    
    # Delete the expense
    expense_to_delete = expenses[0]  # Get the first result (there should only be one)
    db.session.delete(expense_to_delete)
    db.session.commit()
    
    return jsonify({'message': 'Product deleted successfully'})

 
# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
 
 