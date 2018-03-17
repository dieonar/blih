
var crypto      = require('crypto');
var request     = require('request');

module.exports = class Blih {
    constructor(login, password) {
        this.login = login,
        this.token = this.GenerateToken(password);
        this.baseurl = "https://blih.epitech.eu/";

        this.Repository = new Repository(this);
        this.SSHKeys = new SSH(this);
    }

    GenerateToken(password) {
        var hash = crypto.createHash('sha512');
        hash = hash.update(password, 'utf8').digest('hex');
        return hash;
    }

    Request(options, callback) {

        var result = {
            error: null,
        }

        var signature = {
            user: this.login,
            signature: ""
        }

        var hash = crypto.createHmac('sha512', this.token);
        hash.update(this.login);

        if (options.data !== undefined) {
            hash.update(JSON.stringify(options.data, null, 4));
            signature.data = options.data;
        }

        signature.signature = hash.digest('hex').toString();
        
        request({
            uri: this.baseurl + options.path,
            method: options.method,
            json: signature
        }, function (error, response, body) {
            if (error)
                result.error = error;

            if (body.error) {
                result.error = body.error;
                return callback(result);
            }
            result.body = body;
            callback(result);
        });
    }   

    Whoami(callback) {
        this.Request({
            method: 'GET',
            path: "whoami"
        }, callback);
    }
}

class Repository {
    constructor(blih) {
        this.blih = blih;
    }

    GetAlls(callback) {
        this.blih.Request({
            method: 'GET',
            path: "repositories"
        }, callback);
    }

    Get(name, callback) {
        this.blih.Request({
            method: 'GET',
            path: "repository/" + name
        }, callback);
    }

    Create(name, callback) {
        this.blih.Request({
            method: "POST",
            path: "repositories",
            data: {
                name: repository,
                type: "git"
            }
        }, callback)
    }

    Delete(name, callback) {
        this.blih.Request({
            method: "DELETE",
            path: "repository/" + name
        }, callback)
    }

    GetACLs(repository, callback) {
        this.blih.Request({
            method: "GET",
            path: "repository/" + repository + "/acls"
        }, callback)
    }

    SetACL(repository, username, rights, callback) {
        this.blih.Request({
            method: "DELETE",
            path: "repository/" + repository + "/acls",
            data: {
                acl: rights, user: username
            }
        }, callback)
    }
}

class SSH {
    constructor(blih) {
        this.blih = blih;
    }

    GetAlls(callback) {
        this.blih.Request({
            method: 'GET',
            path: "sshkeys"
        }, callback);
    }

    Create(key, callback) {
        this.blih.Request({
            method: 'POST',
            path: "sshkey",
            json: {
                sshkey: key
            }
        }, callback);
    }
    
    Delete(key, callback) {
        this.blih.Request({
            method: 'DELETE',
            path: "sshkey/" + key,
        }, callback);
    }
}
