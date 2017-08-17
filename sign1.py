from burp import IBurpExtender
from burp import ISessionHandlingAction
from burp import IParameter
import hashlib
import hmac
import re
from java.io import PrintWriter

class BurpExtender(IBurpExtender, ISessionHandlingAction):

    #
    # implement IBurpExtender
    #
    # Add your data here:
    projectUrl='https://example.com:443'
    apiKey='123123123123123'
    login='pentester'

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName("Hmac Sign 1")
        callbacks.registerSessionHandlingAction(self)
        return


    def performAction(self, currentRequest, macroItems):
        # analyzing packet and request information
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        headers = list(requestInfo.getHeaders())
        msgBody = currentRequest.getRequest()[requestInfo.getBodyOffset():]
        newHeaders = headers

        # analyzing url and preparing it for hmac sign
        url = str(requestInfo.getUrl())
        url = url.replace(projectUrl,'')
        url = url.split('?', 1)[0]
        print url
        parameters = requestInfo.getParameters()
        parameterArray = []
        stringParameters = ''
        parameters = parameterArray + parameters
        parameters = sort(parameters)
        for p in parameters:
            if p.getName() != '' and p.getValue() != '':
                stringParameters += p.getName() + "=" + p.getValue() + ';'
        stringParameters = stringParameters[:-1]
        sort(stringParameters)
        print stringParameters
        # combining hash string and signing it
        hashstring = url + ';' + stringParameters
        print hashstring
        # if hmac password changed, replace it:
        digest_maker = hmac.new(apiKey,'', hashlib.sha1)

        digest_maker.update(hashstring)

        digest = digest_maker.hexdigest()
        # making header info
        for i in headers:
            if re.search('X-Authorization:', i) != None:
                newHeaders.remove(i)
        # first word (login)
        Authorize = 'X-Authorization: ' + login + " " + str(digest)

        # Add Custom Hash Header Here
        newHeaders.append(Authorize)

        # Build new Http Message with the new Hash Header

        message = self._helpers.buildHttpMessage(newHeaders, msgBody)

        # Print Header into UI if you need to

        #print self._helpers.bytesToString(message)

        # Update Request with New Header

        currentRequest.setRequest(message)

        return
