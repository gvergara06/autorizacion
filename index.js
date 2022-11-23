const crypto = require('crypto');
const SecretsManager = require('./SecretsManager');


const secretName = process.env.secretName;
const region = process.env.region;
const keysecret = process.env.keysecret;

exports.handler = async function(event, context, callback) {
    
    
    var apiValue = await SecretsManager.getSecret(secretName, region);
    var secreto = JSON.parse(apiValue)[keysecret];



    var firma = signature(JSON.stringify(event.body),secreto);
    console.log("firma:::"+firma);
    var token = event.headers.signature;
    
    switch (token) {
        case 'allow':
            callback(null, generatePolicy('user', 'Allow', event.methodArn));
            break;
        case 'deny':
            callback(null, generatePolicy('user', 'Deny', event.methodArn));
            break;
        case 'unauthorized':
            callback("Unauthorized");   // Return a 401 Unauthorized response
            break;
        default:
            callback("Error: Invalid token"); // Return a 500 Invalid token response
    }
};

// Help function to generate an IAM policy
var generatePolicy = function(principalId, effect, resource) {
    var authResponse = {};
    
    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument = {};
        policyDocument.Version = '2012-10-17'; 
        policyDocument.Statement = [];
        var statementOne = {};
        statementOne.Action = 'execute-api:Invoke'; 
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    
    // Optional output with custom properties of the String, Number or Boolean type.
    authResponse.context = {
        "stringKey": "stringval",
        "numberKey": 123,
        "booleanKey": true
    };
    return authResponse;
}

var signature = function(body, apikey){
    console.log("BODY en signature :::"+body);
    console.log("apikey en signature :::"+apikey);

    var hash = crypto.createHash('sha512');
    var data = hash.update(body+apikey,'utf-8');
    var gen_hash= data.digest('hex');
    return gen_hash;
} 