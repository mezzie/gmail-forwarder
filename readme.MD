# GMail Forwarder
The goal of this project is to forward an email from a given label to a list of recipients and move the email after to a new label.

## Compile
```
./gradlew clean build jar
```

## Usage
```
java -jar gforwarder-1.0.jar credentials.json recipients.json reviewer reviewer/forwarded
```

## Create credentials.json
Go to https://console.cloud.google.com/apis/credentials and create an OAuth 2 Client ID and download the json.

## recipients.json

```
{
  "to": ["sample@sample.com", "sample2@sample.com"]
}
```