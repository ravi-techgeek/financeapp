from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

@app.route('/data')
def index():
    # Connect to the database
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Query the database
    c.execute('SELECT * FROM user')
    data = c.fetchall()

    # Render the HTML template with the data
    return render_template('data.html', data=data)
    

if __name__ == '__main__':
    app.run(debug=True)
