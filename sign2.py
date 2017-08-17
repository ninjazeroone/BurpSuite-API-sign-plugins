from burp import IBurpExtender
from burp import ISessionHandlingAction
from burp import IParameter
import hashlib
import hmac
import base64
import urllib
from java.io import PrintWriter

class BurpExtender(IBurpExtender, ISessionHandlingAction):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName("Hmac Sign 2")
        callbacks.registerSessionHandlingAction(self)
        return


    def performAction(self, currentRequest, macroItems):
	#Add your data here:
        key = '123123123123123123'
	projectUrl = 'https://example.com:443'
	projectHost = 'example.com'
        def sign(key, msg):
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

        def prepareToParameter(string):
            string = base64.b64encode(string)
            string = urllib.quote(string, safe='')
            return string

        # analyzing packet and request information
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        headers = list(requestInfo.getHeaders())
        msgBody = currentRequest.getRequest()[requestInfo.getBodyOffset():]
        newHeaders = headers
        url = str(requestInfo.getUrl())
        parameters = requestInfo.getParameters()
        method = 'GET'


        # analyzing url and preparing it for hmac sign
        def formUrl(url):
            url = url.replace(projectUrl,'')
            url = url.split('?', 1)[0]
            print url
            return url

        def formParameters(parameters):
            parameterArray = []
            stringParameters = ''
            parameters = parameterArray + parameters
            for p in parameters:
                if p.getName() != '' and p.getValue() != '':
                    if p.getName() != 'Signature':
                        stringParameters += p.getName() + "=" + p.getValue() + '&'
            stringParameters = stringParameters[:-1]
            print stringParameters
            return stringParameters

        def paramCheck(parameters):
            for p in parameters:
                if p.getName() == 'Signature':
                    return True
            return False

        def makeMsg(requestMethod, url, path, stringParameters):
            # combining hash string
            crlf = '\n'
            hashstring = requestMethod + crlf + url + crlf + path + crlf + stringParameters
            print hashstring
            return hashstring

        def postToOutput(digest):

            signedParameter = self._helpers.buildParameter('Signature', digest, IParameter.PARAM_URL)
            return signedParameter

        paramTrigger = False

        if len(parameters) != 0:
            paramTrigger = paramCheck(parameters)
            parameters = formParameters(parameters)

        else:
            parameters = ''

        print paramTrigger

        # Build new Http Message with the new Hash Header

        toSign = makeMsg(method, projectHost, '/', parameters)

        encodedDigest = sign(key, toSign)
        encodedDigest = prepareToParameter(encodedDigest)

        print encodedDigest

        par = postToOutput(encodedDigest)
        message = self._helpers.buildHttpMessage(newHeaders, msgBody)

        if paramTrigger == False:
            message = self._helpers.addParameter(message, par)

        else:
            message = self._helpers.updateParameter(message, par)

        # Print Header into UI if your need to

        #print self._helpers.bytesToString(message)

        # Update Request with New Header

        currentRequest.setRequest(message)

        return
