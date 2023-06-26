/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 * @author stephane.orluc@forgerock.com
 */


package com.idnow.idnowAuthNode;

import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Set;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;

import javax.inject.Inject;
import javax.net.ssl.HttpsURLConnection;

import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.util.Strings;
import org.forgerock.util.i18n.PreferredLocales;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdUtils;

/**
 * A node that checks to see if zero-page login headers have specified username and whether that username is in a group
 * permitted to use zero-page login headers.
 */
@Node.Metadata(//outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
            outcomeProvider = idnowAuthNode.idnowAuthNodeOutcomeProvider.class,
               configClass      = idnowAuthNode.Config.class,
               tags = {"mfa"})
public class idnowAuthNode //extends AbstractDecisionNode {
    implements Node {

	private static final String BUNDLE = idnowAuthNode.class.getName().replace(".","/");
    private final Logger logger = LoggerFactory.getLogger(idnowAuthNode.class);
    private final Config config;
    private final Realm realm;

    /**
     * Configuration for the node.
     */
    public interface Config {
    // To choose the action to perform with the node
        @Attribute(order = 50)
        default idnowAction actionSelection() {
            return idnowAction.AUTH;
        }
        /**
         * idnow API Key
         */
        @Attribute(order = 100)
        default String idnAPIKey() {
            return "";
        }
        /**
         * idnow customer ID
         */
        @Attribute(order = 200)
        default String idnCustomer() {
            return "forgerock";
        }
        /**
         * idnow Application to use
         */
        @Attribute(order = 300)
        default String idnApplication() {
            return "with-asr";
        }
        /**
         * idnow Configuration to use
         */
        @Attribute(order = 400)
        default String idnAppConfig() {
            return "with-asr-20-8-3";
        }
        /**
         * idnow API base URI
         */
        @Attribute(order = 500)
        default String idnBaseURI() {
            return ".idnow.io/v1/apps/";
        }
        /**
         * idnow Enroll/UnEnroll voice URI
         * Action depends on HTTP action : 
         * POST: Enroll a voice signature
         * DELETE: Un-enroll a voice signature
         */
        @Attribute(order = 700)
        default String idnEnrollURI() {
            return "/enroll";
        }
        /**
         * idnow Authentication voice URI
         */
        @Attribute(order = 800)
        default String idnAuthURI() {
            return "/auth";
        }
        /**
         * Defines the attribute in user profile where to store idnow user id
         * jsonResultCheckVoice.id
         */
        @Attribute(order = 900)
        default String idnIdAttributeInProfile() {
            return "fr-attr-istr2";
        }
        /**
         * Defines the attribute in user profile where to store idnow Revoke links
         * "api_link:"+jsonResultCheckVoice.revocation.api_link,
         * "signature_secret_password:"+jsonResultCheckVoice.revocation.signature_secret_password,
         * "ui_link:"+jsonResultCheckVoice.revocation.ui_link
         */
        @Attribute(order = 1000)
        default String idnRevokeAttributeInProfile() {
            return "fr-attr-imulti1";
        }
        /**
         * Store Voice signature in FOrgeRock user's profile?
         */
        @Attribute(order = 1100)
        default boolean idnStoreSignInFR() {
            return false;
        }
        /**
         * Defines the attribute in user profile where to store 
         * idnow user's signature
         */
        @Attribute(order = 1200)
        default String idnVoiceSignature() {
            return "";
        }
        /**
         * Title to display on the page where the voice is recorded 
         */
        @Attribute(order = 1300)
        default String pageTitle() {
            return "Record your voice";
        }
        /**
         * Message to display on the page where the voice is recorded 
         */
        @Attribute(order = 1400)
        default String pageMessage() {
            return "Please read the text below";
        }
        /**
         * The script to send to client to record the voice to enroll
         *
         * @return The script configuration.
         *
        @Attribute(order = 1500)
        @ScriptContext(AUTHENTICATION_TREE_DECISION_NODE_NAME)
        default Script idnEnrollScript() {
            return Script.EMPTY_SCRIPT;
        }

        /**
         * The script to send to client to record the voice to authenticate
         *
         * @return The script configuration.
         *
        @Attribute(order = 1600)
        @ScriptContext(AUTHENTICATION_TREE_DECISION_NODE_NAME)
        default Script idnAuthScript() {
            return Script.EMPTY_SCRIPT;
        }
*/
    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm The realm the node is in.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public idnowAuthNode(@Assisted Config config, @Assisted Realm realm) throws NodeProcessException {
        this.config = config;
        this.realm = realm;
    }

    /* (non-Javadoc)
     * @see org.forgerock.openam.auth.node.api.Node#process(org.forgerock.openam.auth.node.api.TreeContext)
     */
    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
        String username = null;
        AMIdentity userIdentity = null;
        String idnId = null;

        logger.debug("idnowAuthNode - Process - start");

        NodeState state = context.getStateFor(this);

        if (state.isDefined(org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME)) {
            username = state.get(org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME).asString();
            logger.debug("idnowAuthNode - Process - username: " + username);

            userIdentity = IdUtils.getIdentity(username, realm.asDN());
            try {
                if (userIdentity.isExists() && !userIdentity.getAttribute(config.idnIdAttributeInProfile()).isEmpty()){
                    idnId = userIdentity.getAttribute(config.idnIdAttributeInProfile()).iterator().next();
                } else {
                    idnId = "";
                }
            } catch (SSOException | IdRepoException e) {
                logger.error("idnowAuthNode - Process: SSOException | IdRepoException: " + e.getMessage());
                return Action.goTo(idnowAuthNodeOutcome.FALSE.getOutcome().id).build();
            }
            logger.debug("idnowAuthNode - Process - idnId: " + idnId);


        } else {
            logger.error("idnowAuthNode - Process - Username is required ");
            return Action.goTo(idnowAuthNodeOutcome.FALSE.getOutcome().id).build();
        }

        /* 
         *  If there is no callback, then first of all call idnow for a token and 
         *  then display record your voice page
         */ 
		if (context.getAllCallbacks().isEmpty() && 
            !config.actionSelection().getValue().equals(idnowAction.UNENROLL.getValue())){
            logger.debug("idnowAuthNode - Process - context.getAllCallbacks().isEmpty(): "+
                context.getAllCallbacks().isEmpty()
            );
            /*
             * Call idnow REST API To get a token and ASR phrase
             */
            String idnActionURI = (config.actionSelection().getValue().equals(idnowAction.AUTH.getValue()))?config.idnAuthURI():config.idnEnrollURI();

            JSONObject idnResp = callidnow(
                config.idnAPIKey(),config.idnCustomer(),config.idnApplication(),
                config.idnAppConfig(), config.idnBaseURI(), idnActionURI,
                config.idnStoreSignInFR(), "","", "", 
                context.request.locales.getPreferredLocale().toLanguageTag());
            /*  
             * Return the ScriptTextOutputCallback and the 
             * HiddenValueCallback callbacks to dispay the
             * voice recorder to the enduser and send it in
             * the hidden value "clientScrpitOutputData". 
             */
            HiddenValueCallback hiddenValueCallback = new HiddenValueCallback(
                bundle.getString("hiddenValueCallback.value"), "false");
            try{
                state.putShared("voiceRecordedtoken", idnResp.get("token").toString());
                ScriptTextOutputCallback scriptTextOutputCallback = 
                    new ScriptTextOutputCallback(createScript( idnResp.get("text").toString(),config.pageTitle(),config.pageMessage()));
                return Action.send(hiddenValueCallback,scriptTextOutputCallback).build();
             } catch (JSONException e) {
                logger.error("idnowAuthNode - Process: JSONException " + e.getMessage());
                return Action.goTo(idnowAuthNodeOutcome.FALSE.getOutcome().id).build();
            }
            
        } else {
            if (config.actionSelection().getValue().equals(idnowAction.AUTH.getValue())||
                config.actionSelection().getValue().equals(idnowAction.ENROLL.getValue())) {
                logger.error("idnowAuthNode - Process - AUTH or ENROLL Action");
             
                Optional<String> result = context.getCallback(HiddenValueCallback.class)
                        .map(HiddenValueCallback::getValue).filter(scriptOutput -> !Strings.isNullOrEmpty(scriptOutput));
                String recordedVoice = "";
                if (result.isPresent()) {
                    recordedVoice = result.get();
                }
                /*
                 * Call idnow REST API with the token and the voice to check it
                 */

                String idnActionURI = (config.actionSelection().getValue().equals(idnowAction.AUTH.getValue()))?config.idnAuthURI():config.idnEnrollURI();

                JSONObject idnResult = callidnow(
                    config.idnAPIKey(),config.idnCustomer(),config.idnApplication(),
                    config.idnAppConfig(), config.idnBaseURI(),idnActionURI, config.idnStoreSignInFR(), 
                    state.get("voiceRecordedtoken").toString().replace("\"", ""), 
                    idnId, recordedVoice, context.request.locales.getPreferredLocale().toLanguageTag());
                
                state.remove("voiceRecordedtoken");

                logger.error("idnowAuthNode - Process - idnResult: " + idnResult);

                try {
                    if (!idnResult.has("errorCode")){
                        if (config.actionSelection().getValue().equals(idnowAction.ENROLL.getValue())){
                            // Store the id of the signature if we are enrolling
                            logger.debug("idnowAuthNode - Process - idnResult.get(\"id\"): " + idnResult.get("id"));

                            Map<String, Set<String>> map = new HashMap<String, Set<String>>() {{
                                put(config.idnIdAttributeInProfile(), Collections.singleton(idnResult.get("id").toString()));
                            }};
                    
                            //Try and save against the user profile
                            try {
                                userIdentity.setAttributes(map);
                                userIdentity.store();
                            } catch (IdRepoException | SSOException e) {
                                logger.error("idnowAuthNode - Process: SSOException | IdRepoException: " + e.getMessage());
                                return Action.goTo(idnowAuthNodeOutcome.FALSE.getOutcome().id).build();
                            }
                        } else {
                            // Do nothing if we just authenticate
                        }
                        return Action.goTo(idnowAuthNodeOutcome.TRUE.getOutcome().id).build();
                    } else if (idnResult.getInt("errorCode") == 400){
                        return Action.goTo(idnowAuthNodeOutcome.UNREGISTERED.getOutcome().id).build();
                    } else if (idnResult.getInt("errorCode") == 404){
                        return Action.goTo(idnowAuthNodeOutcome.UNREGISTERED.getOutcome().id).build();
                    } else {
                        return Action.goTo(idnowAuthNodeOutcome.FALSE.getOutcome().id).build();
                    }
                } catch (JSONException e) {
                    logger.error("idnowAuthNode - Process: JSONException " + e.getMessage());
                    return Action.goTo(idnowAuthNodeOutcome.FALSE.getOutcome().id).build();
                }

            } else if (config.actionSelection().getValue().equals(idnowAction.UNENROLL.getValue())) {
                logger.debug("idnowAuthNode - Process - UNENROLL Action");
            } else {
                return Action.goTo(idnowAuthNodeOutcome.FALSE.getOutcome().id).build();
            }

        }
        return Action.goTo(idnowAuthNodeOutcome.FALSE.getOutcome().id).build();

    }

    public enum idnowAction {
		/** Authenticate */
		AUTH("AUTH"),
		/** Enroll */
		ENROLL("ENROLL"),
		/** UNENROLL */
		UNENROLL("UNENROLL");

		private String value;

		/**
		 * The constructor.
		 * @param value the value as a string.
		 */
		idnowAction(String value) {
			this.value = value;
		}

		/**
		 * Gets the action preference value.
		 * @return the value.
		 */
		public String getValue() {
			return value;
		}

	}

    private String createScript (String text, String title,String message) {
        /*
         * TODO load the script from an external js file.
         */
        String rand = new String (""+(new Date()).getTime());
        String script = "var div = document.createElement('div');\n" +
                    "div.id = 'voiceRecorder';\n" +
                    "if(document.getElementById('callbacksPanel') && document.getElementById('callbacksPanel').value != ''){\n"+
                        "div.innerHTML = '<div class=\\\"container\\\">'+" +
                                            "'<h2>" + title + "</h2>'+" +
                                            "'<span style=\\\"font-size:20px;\\\">" + message + "</span>'+" +
                                            "'<div style=\\\"font-size:15px; font-style: italic;text-align:left\\\">'+" +
                                                "'" + text + "' +" +
                                            "'</div><br/><audio id=\\\"recorder\\\" muted hidden></audio>'+" +
                                            "'<div>'+" +
                                                "'<button id=\\\"start\\\">Record</button><button id=\\\"stop\\\">Stop Recording</button>'+" +
                                            "'</div><br/>'+" +
                                            "'<span>Saved Recording</span>'+" +
                                            "'<audio id=\\\"player\\\" controls></audio>'+" +
                                            "'<br/>'+" +
                                        "'</div>';\n" +
                        "var cb = document.getElementById('callbacksPanel');\n" +
                    "} else {\n" +
                        "div.innerHTML = '<div class=\\\"container\\\" style=\\\"width:50%\\\">'+" +
                                            "'<h2>" + title + "</h2>'+" +
                                            "'<span style=\\\"font-size:20px;\\\">" + message + "</span>'+" +
                                            "'<div style=\\\"font-size:15px; font-style: italic;text-align:left\\\">'+" +
                                                "'" + text + "' +" +
                                            "'</div><br/><audio id=\\\"recorder\\\" muted hidden></audio>'+" +
                                            "'<div>'+" +
                                                "'<button id=\\\"start\\\">Record</button><button id=\\\"stop\\\">Stop Recording</button>'+" +
                                            "'</div><br/>'+" +
                                            "'<span>Saved Recording</span><br/>'+" +
                                            "'<audio id=\\\"player\\\" controls></audio>'+" +
                                            "'<br/>'+" +
                                        "'</div>';\n" +
                        "var cb = document.getElementsByClassName('page-header')[0];\n" +
                        "document.getElementsByClassName('form login')[0].hidden = true;\n" +
                    "}\n" +
                    "cb.insertBefore(div, cb.firstChild);\n" +
                    "class VoiceRecorder" + rand + " {\n" +
                    "    constructor() {\n" +
                    "        if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {\n" +
                    "            console.log('getUserMedia supported')\n" +
                    "        } else {\n" +
                    "            console.log('getUserMedia is not supported on your browser!')\n" +
                    "        }\n" +
                    "        this.mediaRecorder\n" +
                    "        this.stream\n" +
                    "        this.chunks = []\n" +
                    "        this.isRecording = false\n" +
                    "        this.recorderRef = document.querySelector('#recorder')\n" +
                    "        this.playerRef = document.querySelector('#player')\n" +
                    "        this.startRef = document.querySelector('#start')\n" +
                    "        this.stopRef = document.querySelector('#stop')\n" +
                    "        this.startRef.onclick = this.startRecording.bind(this)\n" +
                    "        this.stopRef.onclick = this.stopRecording.bind(this)\n" +
                    "        this.constraints = {\n" +
                    "            audio: true,\n" +
                    "            video: false\n" +
                    "        }\n" +
                    "    }\n" +
                    "    handleSuccess(stream) {\n" +
                    "        this.stream = stream\n" +
                    "        this.stream.oninactive = () => {\n" +
                    "            console.log('Stream ended!')\n" +
                    "        };" +
                    "        this.recorderRef.srcObject = this.stream\n" +
                    "        this.mediaRecorder = new MediaRecorder(this.stream)\n" +
                    "        this.mediaRecorder.ondataavailable = this.onMediaRecorderDataAvailable.bind(this)\n" +
                    "        this.mediaRecorder.onstop = this.onMediaRecorderStop.bind(this)\n" +
                    "        this.recorderRef.play()\n" +
                    "        this.mediaRecorder.start()\n" +
                    "    }\n" +
                    "    handleError(error) {\n" +
                    "        console.log('navigator.getUserMedia error: ', error)\n"  +
                    "    }\n" +
                    "    onMediaRecorderDataAvailable(e) { this.chunks.push(e.data) }\n" +
                    "    onMediaRecorderStop(e) { \n" +
                    "        const blob = new Blob(this.chunks, { 'type': 'audio/wav' })\n" +
                    "        const audioURL = window.URL.createObjectURL(blob)\n" +
                    "        this.playerRef.src = audioURL\n" +
                    "        this.chunks = []\n" +
                    "        this.stream.getAudioTracks().forEach(track => track.stop())\n" +
                    "        this.stream = null\n" +
                    "        var reader = new FileReader();\n" +
                    "        reader.readAsDataURL(blob);\n" +
                    "        reader.onloadend = function() {\n" +
                    "            var base64data = reader.result;\n" +
                    "            document.getElementById(\"clientScriptOutputData\").value = base64data;\n" +
                    "            document.getElementById(\"loginButton_0\").className = \"btn btn-block mt-3 btn-primary\";\n" +
                    "            document.getElementById(\"loginButton_0\").removeAttribute(\"hidden\");\n" +
                    "            document.getElementsByClassName('form login')[0].removeAttribute(\"hidden\");\n" +
                    "            document.getElementById(\"loginButton_0\").onclick =  function() {  document.getElementById(\"voiceRecorder\").remove(); };\n" +
                    "        }\n" +
                    "    }\n" +
                    "    startRecording() {\n" +
                    "        if (this.isRecording) return\n" +
                    "        this.isRecording = true\n" +
                    "        this.startRef.innerHTML = 'Recording...'\n" +
                    "        this.playerRef.src = ''\n" +
                    "        navigator.mediaDevices\n" +
                                ".getUserMedia(this.constraints)\n" +
                                ".then(this.handleSuccess.bind(this))\n" +
                                ".catch(this.handleError.bind(this))\n" +
                    "    }\n" +
                    "    stopRecording() {\n" +
                    "        if (!this.isRecording) return\n" +
                    "        this.isRecording = false\n" +
                    "        this.startRef.innerHTML = 'Record'\n" +
                    "        this.recorderRef.pause()\n" +
                    "        this.mediaRecorder.stop()\n" +
                    "    }\n" +
                    "}\n" +
                    "window.voiceRecorder = new VoiceRecorder" + rand + "()";
		logger.trace("idnowAuthNode - createScript - script: " + script);
        return script;
    }

    /**
	 * Method used to call idnow REST API
     * @param idnAPIKey idnow API Key
     * @param idnCustomer idnow customer ID
     * @param idnApplication idnow Applicatiion to use
     * @param idnAppConfig idnow Configuration to use
     * @param idnBaseURI idnow API base URI
     * @param idnIsHTTPS Use idnow API with HTTPS
	 * @param idnActionURI URI off the action to perform (/auth, /enroll)
     * @param idnStoreSignInFR Store Voice signature in FOrgeRock user's profile?
     * @param idnToken idnow token (generated for the API Key) to use to use the REST API
	 * @param username login of the user to authenticate
	 * @param voice base64 encoded voice sample (to authenticate or enroll)
	 * @return idnow response (JSON format).
	 */
	private JSONObject callidnow(
        String idnAPIKey, String idnCustomer, String idnApplication, 
        String idnAppConfig, String idnBaseURI, 
        String idnActionURI, Boolean idnStoreSignInFR, String idnToken,
        String idnId, String voice, String language) {

		HttpsURLConnection conn = null;
		BufferedReader br = null;
        DataOutputStream wr = null;
		JSONObject idnResp = null;

        logger.debug("idnowAuthNode - callidnow - start");

        if (voice.isBlank()){
            // If voice is Blank, then it means we are just doing a Get to get an API 
            // Session token and an ASR text
            String strURL = "https://" + idnCustomer + idnBaseURI + idnApplication + '/' + idnAppConfig + idnActionURI;
		    logger.error ("idnowAuthNode - callidnow - URL: " + strURL);
            try{
                URL url = new URL(strURL);
                conn = (HttpsURLConnection) url.openConnection();
                conn.setDoOutput(true);
                conn.setRequestMethod("GET");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Authorization", "Bearer " + idnAPIKey);
                conn.setRequestProperty("Accept-Language", language);
                if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
                    logger.error("Failed - process: HTTP error code : " + conn.getResponseCode());
                } else {    
                    br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
                    JSONTokener tokener = new JSONTokener(br);
                    idnResp = new JSONObject(tokener);
                }
            } catch (JSONException e) {
                logger.error("idnowAuthNode - callidnow - JSONException: " + e.getMessage());
            } catch (UnsupportedEncodingException e) {
                logger.error("idnowAuthNode - callidnow - UnsupportedEncodingException: " + e.getMessage());
            } catch (MalformedURLException e) {
                logger.error("idnowAuthNode - callidnow - MalformedURLException: " + e.getMessage());
            } catch (IOException e) {
                logger.error("idnowAuthNode - callidnow - IOException: " + e.getMessage());
            } finally {
                if (br != null) {
                    try {
                        br.close();
                    } catch (IOException e) {
                        logger.error("idnowAuthNode - callidnow - IOException in finally while closing: " + e.getMessage());
                    }
                }
                if (conn != null) {
                    conn.disconnect();
                }
            }
        } else {
            // If voice is not Blank, then it means we are authenticating or enrolling 
            String strURL = "https://" + idnCustomer + idnBaseURI + idnApplication + '/' + idnAppConfig + idnActionURI;
		    logger.debug("idnowAuthNode - callidnow - URL: " + strURL);
            String result = voice.substring(22);

            try {
                var decodedString = new String(org.forgerock.util.encode.Base64.decode(result),"ISO-8859-1");

                URL url = new URL(strURL);
                conn = (HttpsURLConnection) url.openConnection();
                conn.setDoOutput(true);
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Authorization", "Bearer " + idnToken);
                conn.setRequestProperty("Accept-Language", language);

                // Create the multipart/form-data
                String boundary = new String("----WebKitFormBoundary" + (new Date()).getTime());
                conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
                String rq =null; 
                
                if (idnId.isEmpty()){
                    rq = new String("--" + boundary + "\r\nContent-Disposition:form-data;name=\"file\";filename=\"file.wav\"\r\nContent-Type:audio/wav\r\n\r\n" + 
                            decodedString +"\r\n--" + boundary + "--\r\n");
                } else {
                    rq = new String("--" + boundary + "\r\nContent-Disposition:form-data;name=\"file\";filename=\"file.wav\"\r\nContent-Type:audio/wav\r\n\r\n" + 
                            decodedString + "\r\n--" + boundary + "\r\nContent-Disposition:form-data;name=\"id\"\r\n\r\n" +
                            idnId + "\r\n--" + boundary + "--\r\n");
                }
                logger.debug("idnowAuthNode - callidnow - rq: " + rq);

                // Send post request
                wr = new DataOutputStream(conn.getOutputStream());
                wr.writeBytes(rq);
                wr.flush();

                if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                    br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
                    JSONTokener tokener = new JSONTokener(br);
                    idnResp = new JSONObject(tokener);
                } else if (conn.getResponseCode() == HttpURLConnection.HTTP_CREATED) {
                    br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
                    JSONTokener tokener = new JSONTokener(br);
                    idnResp = new JSONObject(tokener);
                } else if (conn.getResponseCode() == HttpURLConnection.HTTP_ACCEPTED) {
                    br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
                    JSONTokener tokener = new JSONTokener(br);
                    idnResp = new JSONObject(tokener);
                } else {
                    idnResp = new JSONObject();
                    idnResp.put("errorCode", conn.getResponseCode());
                    idnResp.put("errorMessage", conn.getResponseMessage());
                    logger.debug("idnowAuthNode - callidnow - HTTP error code: " + conn.getResponseCode() + " and message: " + conn.getResponseMessage());
                }
            } catch (JSONException e) {
                logger.error("idnowAuthNode - callidnow - JSONException " + e.getMessage());
            } catch (UnsupportedEncodingException e) {
                logger.error("idnowAuthNode - callidnow - UnsupportedEncodingException " + e.getMessage());
            } catch (MalformedURLException e) {
                logger.error("idnowAuthNode - callidnow - MalformedURLException " + e.getMessage());
            } catch (IOException e) {
                logger.error("idnowAuthNode - callidnow - IOException " + e.getMessage());
            } finally {
                if (wr != null) {
                    try {
                        wr.close();
                    } catch (IOException e) {
                        logger.error("idnowAuthNode - callidnow - IOException in finally while closing " + e.getMessage());
                    }
                }
                if (br != null) {
                    try {
                        br.close();
                    } catch (IOException e) {
                        logger.error("idnowAuthNode - callidnow - IOException in finally while closing " + e.getMessage());
                    }
                }
                if (conn != null) {
                    conn.disconnect();
                }
            }
        }
        return idnResp;
	}

	/**
	 * The possible outcomes for the node.
	 */
	public enum idnowAuthNodeOutcome {
		/**
		 * The voice has been authenticated or enrolled.
		 */
		TRUE("True"),
        /**
		 * Signature not found.
		 */
        UNREGISTERED("unregistered"),
		/**
		 * The voice has not been authenticated nor enrolled.
		 */
	    FALSE("False");

		private String displayValue;

		/**
		 * Constructor.
		 * @param displayValue The value which is displayed to the user.
		 */
		idnowAuthNodeOutcome(String displayValue) {
			this.displayValue = displayValue;
		}

		private OutcomeProvider.Outcome getOutcome() {
			return new OutcomeProvider.Outcome(name(), displayValue);
		}
	}
	/**
	 * Provides the outcomes for the node.
	 * */
	public static class idnowAuthNodeOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			List<Outcome> outcomes = new ArrayList<>();
			outcomes.add(idnowAuthNodeOutcome.TRUE.getOutcome());
			outcomes.add(idnowAuthNodeOutcome.FALSE.getOutcome());

            if (nodeAttributes.isNotNull()) {
				// nodeAttributes is null when the node is created
				if (nodeAttributes.get("actionSelection").asString().equals(idnowAction.AUTH.getValue()) ||
                    nodeAttributes.get("actionSelection").asString().equals(idnowAction.UNENROLL.getValue())) {
                            outcomes.add(idnowAuthNodeOutcome.UNREGISTERED.getOutcome());
				}
			}
			return outcomes;
		}  
	}
}