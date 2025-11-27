# main flask application
from flask import Flask, request
from config import GROUP_SEED, HASH_METHOD, DEFENSE_METHODS

app = Flask(__name__)

@app.route("/")
def home_page():
    """ 
        simple home page, we added a bit of styling to make it look a little nicer, 
        although the main experiement is done through the endpoints.
    """
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cybersecurity course project</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #121212;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .container {
                text-align: center;
                background: #1e1e1e;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.6);
            }
            h1 {
                color: #ffffff;
                margin-bottom: 10px;
            }
            p {
                color: #bbbbbb;
                font-size: 18px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Intro to Cybersecurity testing ground</h1>
            <p>Course Project</p>
        </div>
    </body>
    </html>
    '''

if __name__ == "__main__":
    app.run(debug=False)