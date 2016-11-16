"""
Sample Flask Login app with KnuVerse AudioPass.

Credit: https://github.com/shekhargulati/flask-login-example
"""

from flask import Flask, Response, redirect, request, abort, escape, \
    send_from_directory
from flask.ext.login import LoginManager, UserMixin, \
    login_required, login_user, logout_user

from knuverse import BadRequestException
from knuverse.knufactor import Knufactor

# read in API key
APIKEY_FILE = "admin-apiKey.txt"
with open(APIKEY_FILE, 'r') as fd:
    akf_lines = fd.readlines()

apikey = akf_lines[0].split()[-1]
apisecret = akf_lines[1].split()[-1]

# knuverse sdk
kv = Knufactor(apikey, apisecret)

app = Flask(__name__)

# config
app.config.update(
    DEBUG=True,
    SECRET_KEY='secret_xxx'
)

# flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth"


# silly user model
class User(UserMixin):

    def __init__(self, id):
        self.id = id
        self.name = id
        self.password = self.name + '_secret'

    def __repr__(self):
        return "%d/%s/%s" % (self.id, self.name, self.password)


# create users that are enrolled in knuverse
usernames = [i['name'] for i in kv.get_clients()]
users = [User(i) for i in usernames]


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.root_path, 'favicon.png')


# some protected url
@app.route('/')
@login_required
def home():
    return Response("You are now viewing secret content!")


# Start a verification attempt
@app.route("/auth", methods=["GET", "POST"])
def auth():
    if request.method == 'POST':
        username = request.form['username']

        # request user token from knufactor
        try:
            token = kv.auth_grant(username)['jwt']
        except BadRequestException:
            token = ""
        return redirect(
            "/auth2?token=%s&username=%s" % (escape(token), username)
        )
    else:
        return Response('''
        <form action="" method="post">
            <p><input type=text name=username placeholder=username>
            <p><input type=submit value=Next>
        </form>
        ''')


# Check a verification
@app.route("/auth2", methods=["GET", "POST"])
def auth2():
    if request.method == 'GET':
        utoken = request.args['token']
        username = request.args['username']
        return Response('''
<script src="https://cloud.knuverse.com/verifyme/js/knuverse_agent.js">
</script>
<script>
KnuVerse.configure();
var params = {token: '%s'};
var callBackFunction = function(data) {
    console.log(data.token);
    console.log(data.verificationId);
    document.getElementById("token").value = data.token;
    document.getElementById("vid").value = data.verificationId;
    document.submitform.submit();
}.bind(this);
// this must be called by user action.
// otherwise, popup will be blocked.
    var startVerification = function() {
    if (params.token) {
        KnuVerse.startVerification(params, callBackFunction);
    } else {
        document.submitform.submit();
    }
    return false;
};
</script>
<p>MFA Challenge</p>
    <form name=submitform onsubmit="return startVerification();" method="post">
    <input type=hidden name="username" value="%s"/>
    <input type=hidden name="token" id="token"/>
    <input type=hidden name="vid" id="vid"/>
    <input type=password name=password placeholder="<username>_secret">
    <button type=submit>Next</button>
</form>

        ''' % (utoken, username))
    else:
        username = request.form['username']
        ctoken = request.form['token']
        vid = request.form['vid']
        password = request.form['password']

        if ctoken:
            # request user token from knufactor
            ver = kv.get_verification_resource_secure(
                vid, ctoken, username)
            verified = ver['verified']
        else:
            verified = True

        # kick out if not a valid user
        if username not in usernames:
            return abort(401)

        if verified and password == (username + "_secret"):
            user = User(username)
            login_user(user)
            return redirect("/")
        else:
            return abort(401)


# somewhere to logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return Response('<p>Logged out</p>')


# handle login failed
@app.errorhandler(401)
def page_not_found(e):
    return Response('<p>Login failed</p>')


# callback to reload the user object
@login_manager.user_loader
def load_user(userid):
    return User(userid)

if __name__ == "__main__":
    app.run()
