"""
Sample Flask Login app with KnuVerse AudioPass.

Credit: https://github.com/shekhargulati/flask-login-example
"""

from flask import Flask, Response, redirect, request, abort, escape, \
    send_from_directory
from flask_login import LoginManager, UserMixin, \
    login_required, login_user, logout_user
import json

from knuverse.exceptions import BadRequestException, NotFoundException, ForbiddenException
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
        role = request.form['role']
        mode = request.form['mode']

        # request user token from knufactor
        try:
            token = kv.auth_grant(username, role, mode)['jwt']
        except (BadRequestException, NotFoundException, ForbiddenException) as e:
            error = "An error occurred. Please try again."
            if e.args and e.args[0]:
                error = json.loads(e.args[0]).get("error", error)
            return Response('''
            <p>%s</p>
            ''' % error)
        return redirect(
            "/auth2?token=%s&username=%s&role=%s" % (escape(token), username, role)
        )
    else:
        return Response('''
        <form action="" method="post">
            <p><input type=text name=username placeholder=username>
            <div>
                <label for="role">Role</label>
                <select name="role">
                    <option value="grant_enroll_verify">Grant_Enroll_Verify</option>
                    <option value="grant_enroll">Grant_Enroll</option>
                    <option value="grant_verify">Grant_Verify</option>
                </select>
            </div>
            <div>
                <label for="mode">Mode</label>
                <select name="mode">
                    <option value="audiopass">AudioPass</option>
                    <option value="audiopin">AudioPIN</option>
                </select>
            </div>
            <p><input type=submit value=Next>
        </form>
        ''')


# Check a verification
@app.route("/auth2", methods=["GET", "POST"])
def auth2():
    if request.method == 'GET':
        utoken = request.args['token']
        username = request.args['username']
        role = request.args['role']
        return Response('''
<script src="https://cloud.knuverse.com/verifyme/js/knuverse_agent.min.js">
</script>
<script>
var role = '%s';
var params = {token: '%s'};
var verificationCallBackFunction = function(data) {
    console.log(data.token);
    console.log(data.verificationId);
    document.getElementById("token").value = data.token;
    document.getElementById("vid").value = data.verificationId;
    document.submitform.submit();
}.bind(this);
var enrollmentCallBackFunction = function(data) {
    console.log(data.token);
    console.log(data.enrollmentId);
    if (role === 'grant_enroll') {
        alert('Enrollment completed. Please select the "Grant_Verify" or "Grant_Enroll_Verify" token to verify');
        window.location.href = '/';
    }
};
// this must be called by user action.
// otherwise, popup will be blocked.
    var startVerification = function() {
    if (params.token) {
        KnuVerse.multiFactorAuthentication(params, verificationCallBackFunction, enrollmentCallBackFunction);
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

        ''' % (role, utoken, username))
    else:
        username = request.form['username']
        ctoken = request.form['token']
        vid = request.form['vid']
        password = request.form['password']

        verified = False
        if ctoken:
            # request user token from knufactor
            ver = kv.verification_resource_secure(
                vid, ctoken, username)
            verified = ver['verified']

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
