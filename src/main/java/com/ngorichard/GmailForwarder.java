package com.ngorichard;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.AbstractInputStreamContent;
import com.google.api.client.http.ByteArrayContent;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.Base64;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.GmailScopes;
import com.google.api.services.gmail.model.*;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.mail.Address;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

/**
 * 
 */
public class GmailForwarder {
    private static final String APPLICATION_NAME = "gmail forwarder";
    private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
    private static final String TOKENS_DIRECTORY_PATH = "tokens";
    private static final Logger logger = LoggerFactory.getLogger(GmailForwarder.class);
    /**
     * Global instance of the scopes required by this quickstart.
     * If modifying these scopes, delete your previously saved tokens/ folder.
     */
    private static final List<String> SCOPES = Collections.singletonList(GmailScopes.MAIL_GOOGLE_COM);

    private static Gmail service;
    /**
     * Creates an authorized Credential object.
     * @param HTTP_TRANSPORT The network HTTP Transport.
     * @return An authorized Credential object.
     * @throws IOException If the credentials.json file cannot be found.
     */
    private static Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT, final String credetialsPath) throws IOException {
        // Load client secrets.
        InputStream in;
        if(credetialsPath != null) {
            in = new FileInputStream(credetialsPath);
        } else {
            throw new NullPointerException("Credentials can't be null, get it from https://console.cloud.google.com/apis/credentials OAuth 2.0 Client ID and download the json");
        }

        GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(in));

        // Build flow and trigger user authorization request.
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, SCOPES)
                .setDataStoreFactory(new FileDataStoreFactory(new java.io.File(TOKENS_DIRECTORY_PATH)))
                .setAccessType("offline")
                .build();
        return new AuthorizationCodeInstalledApp(flow, new LocalServerReceiver()).authorize("user");
    }

    private static String fromLabelId;
    private static String toLabelId;

    public static void main(String... args) throws IOException, GeneralSecurityException {
        // Build a new authorized API client service.
        logger.info("init");
        String credentialsPath = null, recipients = null, from = null, to = null;
        if(args.length == 0) {
            System.out.println("Usage: java -jar gforwarder-1.0.jar <<PATH TO google OAUTH 2.0 Client json>> <<Recipients json>> <<label from>> <<label to>>");
            System.out.println("Example: java -jar gforwarder-1.0.jar credentials.json recipients.json reviewer reviewer/forwarded");
            System.exit(0);
        }
        if(args.length > 0){
            credentialsPath = args[0];
            from = args[1];
            to = args[2];
        }
        final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
        service = new Gmail.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT, credentialsPath))
                .setApplicationName(APPLICATION_NAME)
                .build();

        // Print the labels in the user's account.
        String user = "me";
        ListLabelsResponse listResponse = service.users().labels().list(user).execute();
        List<Label> labels = listResponse.getLabels();
        if (labels.isEmpty()) {
            logger.error("No labels found. exiting");
            System.exit(-1);
        } else {
            for (Label label : labels) {
                if(label.getName().equals(from)) {
                    fromLabelId = label.getId();
                    if(logger.isDebugEnabled()) {
                        logger.debug("Found from label with ID : ["+ fromLabelId +"]");
                    }
                } else if(label.getName().equals(to)) {
                    toLabelId = label.getId();
                    if(logger.isDebugEnabled()) {
                        logger.debug("Found forwarded label with ID : ["+ toLabelId +"]");
                    }
                }
            }
        }
        if(fromLabelId != null && toLabelId != null) {
            getMails();
        } else {
            throw new IllegalArgumentException(String.format("Did not find labels provided - from [ Name :%s - ID: %s ] | to: [ Name: %s - ID: %s]", from, fromLabelId, to, toLabelId));
        }
    }

    public static void getMails() throws IOException {
        ListMessagesResponse emails = service.users().messages().list("me").setLabelIds(new ArrayList<String>(){{add(fromLabelId);}}).execute();
        if(emails.getMessages() != null){
            logger.info("There are " + emails.getMessages().size() + " messages to be processed");
            for(Message message: emails.getMessages()) {
                fetchEmail(message);
            }
        } else {
            logger.info("There are no message currently to be forwarded");
        }
    }

    public static void fetchEmail(Message msg) throws IOException {
        Message message = service.users().messages().get("me", msg.getId()).setFormat("raw").execute();
        try {
            MimeMessage mimeMessage = getMimeMessage(message);
            logger.info("Processing email with title ["+mimeMessage.getSubject()+"]");

            // Add new recipients
            List<Address> recipients = getJsonRecipients();
            mimeMessage.setRecipients(javax.mail.Message.RecipientType.TO,recipients.toArray(new Address[recipients.size()]));

            logger.info("Just before sending the email");

            // instead of passing in the Message, pass in the bytes directly. This fixes sending big emails
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            mimeMessage.writeTo(baos);
            AbstractInputStreamContent mediaContent = new ByteArrayContent("message/rfc822", baos.toByteArray());
            service.users().messages().send("me", null, mediaContent).execute();
            logger.info("Sending successful with subject [" +mimeMessage.getSubject() + "]");

            // modify, remove the reviewer and put it in reviewer/forwarded
            ModifyMessageRequest mods = new ModifyMessageRequest()
                    .setAddLabelIds(new ArrayList<String>(){{add(toLabelId);}})
                    .setRemoveLabelIds(new ArrayList<String>(){{add(fromLabelId);}});

            logger.debug("From Label ID: ["+ fromLabelId +"] | To Label ID: ["+ toLabelId +"]");
            service.users().messages().modify("me", msg.getId(), mods).execute();
            logger.info("Removed reviewer label for message: ["+mimeMessage.getSubject()+"]");
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    private static List<Address> getJsonRecipients(){
        JsonParser parser = new JsonParser();
        JsonElement recipientsJson = parser.parse(new InputStreamReader(GmailForwarder.class.getResourceAsStream("/recipients.json")));
        JsonArray toRecipientsJson = recipientsJson.getAsJsonObject().get("to").getAsJsonArray();
        List<Address> recipients = new ArrayList<>();
        for( JsonElement recipient: toRecipientsJson ) {
            try {
                logger.info("Adding " + recipient.getAsString() + " to recipients");
                recipients.add(new InternetAddress(recipient.getAsString()));
            } catch (AddressException e) {
                e.printStackTrace();
            }
        }
        return recipients;
    }

    public static MimeMessage getMimeMessage(Message message)
            throws MessagingException {
        byte[] emailBytes = Base64.decodeBase64(message.getRaw());
        Session session = Session.getDefaultInstance(new Properties(), null);
        MimeMessage email = new MimeMessage(session, new ByteArrayInputStream(emailBytes));
        return email;
    }
}