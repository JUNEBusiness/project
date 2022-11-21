# JOURNAL
#### Video Demo:  https://youtu.be/jEJlPiCEi3M
#### Description:
This app (JOURNAL) was designed to help users document their day-to-day activities online and spare them the effort of having to carry heavy journals or diaries.
The text area in the index.html of this app consists of cool functionalities that can be used on the go, like, bold, italicize, underline, paint and much more. I chose the text area from tiny.cloud because of its formatting features.
Its formatting features give users the feeling that they can do more than just write down their thoughts but that they can design it. Although I stripped off the HTML tags that gives it the formatting functionality at the back-end because it is not rendered well on the page in the history section but all tags are rendered as strings and in my opinion makes it badly designed. therefore, to keep it smart, the text input at the text area is stripped off all its designs when reviewing previous entries in the history page.

JOURNAL helps with security as only those who know the password can have access to it unlike a diary or a journal that can be stolen hence the need for my adding a one-time-only password to be chosen. It can't be stolen, it is fire proof and can only be destroyed by the owner or when we have the internet apocalypse or armageddon! "Journal" is a cool app as it is simple to use and navigate.
It consists of five html files saved in the templates folder the layout/base.html inclusive.
The index.html page where you can type your thoughts, the register.html page is where you can sign up, the login.html page is where you log in and the history.html page is where all previous entries can be seen with the most recent entry by date on the top.
To use the app, register with a unique username, password and email. On successful registration, you are good to go. You can now write down your thoughts, one stroke at a time.

JOURNAL basically has six files apart from the virtual environment file, instance, and session that are generated with a single use alone. The flask-session folder contains session files and stores each session for individual users, the instance folder contain the journal.db file that serves as the database, the venv folder contains the scripts and other dependencies and is the name of the virtual environment, while the requirement folder contains the requirements text file that stores all the installation needed for the app to run, the static folder contains files like the css and js files used for styling and enabling some functionality for the web-app, the templates folder contains all the templates that will be rendered per each route the user visits. lastly, the app.py contains the code written for the app to be created and run.
The virtual environment was important to scope any version of plugin or dependencies to the app and made it easier for me to create an accurate requirements.txt file.
The requirements.ttx file contains all the version needed for plugins and libraries/dependency needed for the app to run successfully on another machine or server.
The instance file was created with an app_context since models now also use the session engine a la flask's documentation for sqlalchemy.
