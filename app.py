from flask import Flask, render_template

app = Flask(__name__)

# routes
# ==
# home
@app.route('/')
def main():
    return render_template('main.html')

if __name__ == '__main__':
    print 'starting server'
    app.run(host='0.0.0.0', debug=True)
