# LetsEncrypt for Google AppEngine Python
If you want to have a free SSL certificate from LetsEncrypt for you custom domain, the setup and renewal can be a hassle.
This little script makes the process super easy.

### Note about security
You should probably quickly read through the python script to convince yourself that it's secure.

## Installation
In your Python AppEngine Project execute the following command:
```
git submodule add https://github.com/AirConsole/letsencrypt
```

Then add the following to your `app.yaml`:
```
handlers:
- url: /\.well\-known\/acme\-challenge\/.*
  script: letsencrypt.app
```
Upload your app to Google AppEngine.

## Create or renew a SSL certificate
- Go to `http://www.yourdomain.com/.well-known/acme-challenge/` and login as an administrator
- Execute the displayed command in a shell that supports curl and openssl ([Google Cloud Shell](https://cloud.google.com/shell/docs/quickstart) can be used)
- Upload the obtained certificates on https://console.cloud.google.com/appengine/settings/certificates
