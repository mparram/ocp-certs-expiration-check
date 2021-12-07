const https = require('https');
const prometheus = require('prom-client');
var certinfo = require('cert-info');
const fs = require("fs");
const path = require("path");
var express = require('express');
var bodyParser = require('body-parser');
var app = express();
app.listen(8080, function () { 
    console.log('Listening at http://localhost:8080'); 
});
const apiHost = process.env.KUBERNETES_PORT_443_TCP_ADDR || 'api.ocp.example.com';
const apiPort = process.env.KUBERNETES_PORT_443_TCP_PORT || 6443;
const tokenpath = "/var/run/secrets/kubernetes.io/serviceaccount/token";
// if file tokenpath exists, read it and set apiToken
if (fs.existsSync(tokenpath)) {
    var apiToken = fs.readFileSync(tokenpath, 'utf8');

}else{
    var apiToken = "sha256~___TESTING_ONLY_TOKEN___";
}

// Start Prometheus metrics Registry
const register = new prometheus.Registry();
// Create a new Gauge metric
const metric = new prometheus.Gauge({
    name: 'cert_check_expiration',
    help: 'check the expiration time of the cert in seconds',
    labelNames: ['resource', 'namespace', 'name', 'crt_index', 'object_type']
});
register.registerMetric(metric);

// Express route to present metrics
app.get('/metrics', async (req, res) => {
    res.setHeader('Content-Type', register.contentType);
    res.send(await register.metrics());
});
var resourcesByType = [];

// Read the config file
const resources = JSON.parse(fs.readFileSync(path.resolve(__dirname, "./config/resources.json"), "utf8"));

// Split the resources into different types (secrets/configmaps)
Object.keys(resources).forEach(function (key) {
    resources[key].forEach(function (item) {
        item.resource = key;
        // push to resourcesByType object
        resourcesByType[item.type] = resourcesByType[item.type] || [];
        resourcesByType[item.type].push(item);
    });
});

// First check on boot
checkCert();

// run certCheck every 12 hours
setInterval(function () {
    checkCert();
}, 12 * 60 * 60 * 1000);

function checkCert() {

    // Start with secrets checking
    resourcesByType.secret.forEach(function (item) {
        // if item.name contain "*", will use httpRequestLastIndex to get the last item certs, if not will use httpRequest to get the item certs
        if (item.name.indexOf("*") > -1) {
            //get the last index of "*" in secrets with the same name
            var response = httpRequestLastIndex("secrets", item.namespace, item.name, function (response, err) {
                if (err) {
                    console.log(err);
                }
                //decode base64 response.data[item.config.data]
                let buff = Buffer.from(response.data[item.config.data], 'base64');
                let crt = buff.toString('ascii');
                // split each cert in certs string
                var certs = crt.split("-----BEGIN CERTIFICATE-----");
                var certindex = 0;
                certs.forEach(function (cert) {
                    // remove last empty line from cert
                    cert = cert.replace(/\n$/, "");
                    // if cert is not empty
                    if (cert.length > 0) {
                        cert = "-----BEGIN CERTIFICATE-----" + cert;
                        certindex++;
                        var TTL = checkCertExpiration(cert);
                        // update prometheus metric
                        metric.set({'resource': item.resource, 'namespace': item.namespace, 'name': response.metadata.name, 'crt_index': certindex, 'object_type': item.type}, TTL);
                    }
                });
            });
        }else{
            // get the item certs
            var response = httpRequest("secrets", item.namespace, item.name, function (response, err) {
                if (err) {
                    console.log(err);
                }
                console.log(item.namespace + "/" + item.name + ": " + item.config.data);
                //decode base64 response.data[item.config.data]
                let buff = Buffer.from(response.data[item.config.data], 'base64');
                let crt = buff.toString('ascii');
                // split each cert in certs string
                var certs = crt.split("-----BEGIN CERTIFICATE-----");
                var certindex = 0;
                certs.forEach(function (cert) {
                    // remove last empty line from cert
                    cert = cert.replace(/\n$/, "");
                    // if cert is not empty
                    if (cert.length > 0) {
                        cert = "-----BEGIN CERTIFICATE-----" + cert;
                        certindex++;
                        var TTL = checkCertExpiration(cert);
                        metric.set({'resource': item.resource, 'namespace': item.namespace, 'name': response.metadata.name, 'crt_index': certindex, 'object_type': item.type}, TTL);
                    }
                });
            });
        }
    });
    // Now check configmaps certs
    resourcesByType.configmap.forEach(function (item) {
        // if item.name contain "*", will use httpRequestLastIndex to get the last item certs, if not will use httpRequest to get the item certs
        if (item.name.indexOf("*") > -1) {
            //get the last index of "*" in configmaps with the same name
            var response = httpRequestLastIndex("configmaps", item.namespace, item.name, function (response, err) {
                if (err) {
                    console.log(err);
                }
                console.log(item.namespace + "/" + item.name + ": " + item.config.data);
                //decode base64 response.data[item.config.data]
                let crt = response.data[item.config.data];
                // split each cert in certs string
                var certs = crt.split("-----BEGIN CERTIFICATE-----");
                var certindex = 0;
                certs.forEach(function (cert) {
                    // remove last empty line from cert
                    cert = cert.replace(/\n$/, "");
                    // if cert is not empty
                    if (cert.length > 0) {
                        cert = "-----BEGIN CERTIFICATE-----" + cert;
                        certindex++;
                        var TTL = checkCertExpiration(cert);
                        metric.set({'resource': item.resource, 'namespace': item.namespace, 'name': response.metadata.name, 'crt_index': certindex, 'object_type': item.type}, TTL);
                    }
                });
            });
        }else{
            // get the item certs
            var response = httpRequest("configmaps", item.namespace, item.name, function (response, err) {
                if (err) {
                    console.log(err);
                }
                console.log(item.namespace + "/" + item.name + ": " + item.config.data);
                //decode base64 response.data[item.config.data]
                let crt = response.data[item.config.data];
                // split each cert in certs string
                var certs = crt.split("-----BEGIN CERTIFICATE-----");
                var certindex = 0;
                certs.forEach(function (cert) {
                    // remove last empty line from cert
                    cert = cert.replace(/\n$/, "");
                    // if cert is not empty
                    if (cert.length > 0) {
                        cert = "-----BEGIN CERTIFICATE-----" + cert;
                        certindex++;
                        var TTL = checkCertExpiration(cert);
                        metric.set({'resource': item.resource, 'namespace': item.namespace, 'name': response.metadata.name, 'crt_index': certindex, 'object_type': item.type}, TTL);
                    }
                });
            });
        }
    });
}
//get the last item certs from [secrets/configmaps] matching the name
function httpRequestLastIndex(type, namespace, name, callback) {
    var options = {
        hostname: apiHost,
        rejectUnauthorized: false,
        port: apiPort,
        path: '/api/v1/namespaces/' + namespace + '/' + type,
        headers: {
            "Authorization": "Bearer " + apiToken,
            "Content-Type": "application/json"
        }
    };
    var req = https.get(options, function (res) {
        var body = '';
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
            body += chunk;
        });
        res.on('end', function () {
            var prefix = name.replace(/-\*$/, "");
            var prefix = prefix.replace(/\*/g, "");
            var bodyArr = JSON.parse(body);
            bodyArr = bodyArr.items.filter(function (item) {
                return item.metadata.name.indexOf(prefix) === 0;
            });
            bodyArr.sort(function (a, b) {
                return a.metadata.name.localeCompare(b.metadata.name);
            });
            var lastItem = bodyArr[bodyArr.length - 1];
            callback(lastItem);
        });
    });
}
//get the item certs from [secret/configmap]
function httpRequest(type, namespace, name, callback) {
    var options = {
        hostname: apiHost,
        rejectUnauthorized: false,
        port: apiPort,
        path: '/api/v1/namespaces/' + namespace + '/' + type + '/' + name,
        headers: {
            "Authorization": "Bearer " + apiToken,
            "Content-Type": "application/json"
        }
    };
    var req = https.get(options, function (res) {
        var body = '';
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
            body += chunk;
        });
        res.on('end', function () {
            callback(JSON.parse(body));
        });
    });
}
//check the expiration date of the cert
function checkCertExpiration(cert) {
    var certinfoObj = certinfo.info(cert);
    var expireDate = new Date(certinfoObj.expiresAt);
    var now = new Date();
    var diff = expireDate.getTime() - now.getTime();
    // var days = Math.floor(diff / (1000 * 60 * 60 * 24));
    return diff;
}