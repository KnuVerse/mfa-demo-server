# mfa-demo-server
Demo Flask app integrating with Knufactor

We recommend going through our walkthrough at: https://cloud.knuverse.com/docs/guides/mfawalk

## Note
A minimum python version of 2.7.9 is required to work with our version of TLS(>v1.1)

## CliffsNotes

1. Clone repo

   ```sh
   $ git clone git@github.com:KnuVerse/mfa-demo-server.git
   $ cd mfa-demo-server
   ```

2. Setup environment

   ```sh
   $ virtualenv -p python3 env
   $ source env/bin/activate
   $ pip install -r requirements.txt
   ```

3. Make sure someone is enrolled
    - This demo requires at least 1 client to be enrolled
    - Remember a client name to user as username when attempting to login

4. Create and download an API Key from the Knufactor Console

   1. Go to https://cloud.knuverse.com/app/#/api_keys
      - Navigate to System -> API Keys
   2. Download key via "Create API Key"

5. Move the API key into the repo

   - If you downloaded your API key to your downloads folder, move it to this folder:
   ```sh
   $ mv ~/Downloads/admin-apiKey-XXXX...txt admin-apiKey.txt
   ```

6. Run the app

   ```sh
   (env)$ python app.py
    * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
    * Restarting with stat
    * Debugger is active!
    * Debugger pin code: XXX-XXX-XXX
   ```

7. login
   * You can login with a client name you enrolled with
   * In the MFA challenge form, your password will be "/<username/>_secret"
   * Click Next and perform your voice verification

8. Try Again
   * To logout, goto http://127.0.0.1:5000/logout
   * Repeat step 7

