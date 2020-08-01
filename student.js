"use strict";

/*****************************************************************************
 * This is the JavaScript file that students need to modify to implement the 
 * password safe application.  The other file, client.js, must not be
 * modified.  That file handles page navigation, event handler binding, token 
 * setting/retrieving, preflighting, and provides some utility functions that 
 * this file should use for encoding/decoding strings and making server 
 * requests.
 *
 * Do not use any method other than serverRequest to make requests to the 
 * server!  It handles a few things including tokens that you must not
 * reimplement.
 *
 * Some of the functions in this file handle a form submission.  These 
 * are passed as arguments the input/output DOM elements of the form that was
 * submitted.  The "this" keyword for these functions is the form element 
 * itself.  The functions that handle form submissions are:
 *   - login
 *   - signup
 *   - save
 *
 * The other functions are each called for different reasons with different
 * parameters:
 *   - loadSite -- This function is called to populate the input or output 
 *                 elements of the add or load password form.   The function
 *                 takes the site to load (a string) and the form elements
 *                 as parameters.  It should populate the password form
 *                 element with the decrypted password.
 *   - logout -- This function is called when the logout link is clicked.
 *               It should clean up any data and inform the server to log
 *               out the user.
 *   - credentials -- This is a utility function meant to be used by the
 *                    login function.  It is not called from other client 
 *                    code (in client.js)!  The purpose of providing the
 *                    outline of this function is to help guide students
 *                    towards an implementation that is not too complicated
 *                    and to give ideas about how some steps can be 
 *                    accomplished.
 *
 * The utility functions in client.js are:
 *   - randomBytes -- Takes a number of bytes as an argument and returns
 *                    that number of bytes of crypto-safe random data
 *                    as a hexidecimal-encoded string.
 *   - hash -- Takes a string as input and hashes it using SHA-256.
 *             Returns a promise for the hashed value.
 *   - encrypt -- Takes a plaintext string, a key and an IV and encrypts
 *                the plaintext using AES-CBC with the key and IV.  The
 *                key must be a 32 byte hex-encoded string and the IV must
 *                be a 16 byte hex-encoded string.
 *                Returns a promise for the encrypted value, which is a 
 *                hex-encoded string.
 *   - decrypt -- Takes a ciphertext hex-encoded string, a key and an IV and
 *                decrypts the ciphertext using AES-CBC with the key and IV.
 *                The key must be a 32 byte hex-encoded string and the IV
 *                must be a 16 byte hex-encoded string.
 *                Returns a promise for the decrypted value, which is a 
 *                plaintext string.
 *   - serverRequest -- Takes the server resource and parameters as arguments
 *                      and returns a promise with two properties:
 *                        * response (a JavaScript response object)
 *                        * json (the decoded data from the server)
 *   - showContent -- Shows the specified page of the application.  This is 
 *                    how student code should redirect the site to other
 *                    pages after a user action.
 *   - status -- displays a status message at the top of the page.
 *   - serverStatus -- Takes the result of the serverRequest promise and
 *                     displays any status messages from it.  This just
 *                     avoids some code duplication.
 *
 * A few things you will need to know to succeed:
 * ---------------------------------------------------
 * Look at the MDN documentation for promises!
 *      https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise
 *
 * There are lots of resources online for how to use promises, so go learn
 * about them before starting on the project. It is crucial that students 
 * understand how promises work, since they are used throughout the boilerplate.
 *
 *****************************************************************************/


/**
 * This is an async function that should return the username and password to send
 * to the server for login credentials.
 */
async function credentials(username, password) {
  var idResult;

  // get any information needed to log in
  idResult = await serverRequest("identify", { "username": username });
  // bail if something went wrong
  if (!idResult.response.ok) {
    serverStatus(idResult);
    return 0;
  }

  return idResult.json;
}

var masterUser;
var masterPWD;
var c = 4096;
var len = 256;
var salt;

/**
 * Called when the user submits the log-in form.
 */
function login(userInput, passInput) {
  // get the form fields
  var username = userInput.value,
    password = passInput.value;
    masterPWD = password
    masterUser = username;


  credentials(username, password).then(function (idJson) {
    // do any needed work with the credentials
    var salt = idJson.salt;
    var challenge = idJson.challenge;

    // First perform hash(pwd)
    PBKDF2_SHA256(masterPWD, salt, 4096, 256).then(function (hashedPassword1) {
      var pwdChl = hashedPassword1 + challenge;

      // Then perform hash(hash(pwd) || challenge) & send to server
      PBKDF2_SHA256(pwdChl, salt, 4096, 256).then(function (hashedPassword2) {
        // Send a login request to the server with the hashed password.
        serverRequest("login", // resource to call
          { "username": username, "password": hashedPassword2 } // this should be populated with needed parameters
        ).then(function (result) {
          // If the login was successful, show the dashboard.
          if (result.response.ok) {
            // do any other work needed after successful login here

            // display the user's full name in the userdisplay field
            let userdisplay = document.getElementById("userdisplay");
            // userdisplay refers to the DOM element that students will need to
            // update to show the data returned by the server.
            userdisplay.innerHTML = result.json.fullname;

            showContent("dashboard");

          } else {
            // If the login failed, show the login page with an error message.
            serverStatus(result);
          }
        });

      });
  });

  });
}

// PBKDF2 implemented with SHA256 hashing
async function PBKDF2_SHA256(password, salt, c, len) {
  console.log("STARTING PBKDF2");
  var last = salt.concat("1");

  var xorsum = "0000000000000000000000000000000000000000000000000000000000000000";
  var hashed;
  
  last = await hash(last.concat(password));
  hashed = last;

  for (var i = 1; i < 4096; i++) {
    last = await hash(last.concat(password));
    xorsum = XOR_hex(xorsum, last);
  }

  return xorsum;
}


// https://stackoverflow.com/questions/30651062/how-to-use-the-xor-on-two-strings
function XOR_hex(a, b) {
  var res = "",
    i = a.length,
    j = b.length;
  while (i-- > 0 && j-- > 0)  
    res = (parseInt(a.charAt(i), 16) ^ parseInt(b.charAt(j), 16)).toString(16) + res;
  return res;
}

/**
 * Called when the user submits the signup form.
 */
function signup(userInput, passInput, passInput2, emailInput, fullNameInput) {
  // get the form fields
  var username = userInput.value,
    password = passInput.value,
    password2 = passInput2.value,
    email = emailInput.value,
    fullname = fullNameInput.value;

  // do any preprocessing on the user input here before sending to the server
  // Check if passwords match
  if (password != password2) {
  } else if (password.length < 8) {
    // Ensure password is long enough
    let signup = document.getElementById("signup");

    var errorText = document.createElement("div");
    errorText.innerText = "Please choose a password longer than 8 characters";
    signup.appendChild(errorText)
  } else {
    // send the signup form to the server
    serverRequest("signup",  // resource to call
      { "username": username, "password": password, "email": email, "fullname": fullname } // this should be populated with needed parameters
    ).then(function (result) {
      // if everything was good
      if (result.response.ok) {
        // do any work needed if the signup request succeeded

        // go to the login page
        showContent("login");
      }
      // show the status message from the server
      serverStatus(result);
    });
  }
}

String.prototype.convertToHex = function (delim) {
  return this.split("").map(function (c) {
    return ("0" + c.charCodeAt(0).toString(16)).slice(-2);
  }).join(delim || "");
};


/**
 * Called when the add password form is submitted.
 */
function save(siteIdInput, siteInput, userInput, passInput) {
  var siteid = siteIdInput.value,
    site = siteInput.value,
    siteuser = userInput.value,
    sitepasswd = passInput.value,
    encrypted; // this will need to be populated

  var iv = randomBytes(16);

  // Send the elements to server for storage
  // Pad the master password with '0's
  var hexPWD32B = masterPWD.padEnd(32, '0').convertToHex();

  // Encrypt the password first
  encrypt(sitepasswd, hexPWD32B, iv).then(function (cipher) {
    // cipher is the ciphertext
    encrypted = cipher;

    // send the data, along with the encrypted password, to the server
    serverRequest("save",  // the resource to call
      {"masteruser": masterUser, "siteid": siteid, "site": site, "siteuser": siteuser, "sitePasswdEncr": encrypted, "siteIV": iv} // this should be populated with any parameters the server needs
    ).then(function (result) {
      if (result.response.ok) {
        console.log("Saved password");
        // any work after a successful save should be done here

        // update the sites list
        sites("save");
      }
      // show any server status messages
      serverStatus(result);
    });


  });
}

/**
 * Called when a site dropdown is changed to select a site.
 * This can be called from either the save or load page.
 * Note that, unlike all the other parameters to functions in
 * this file, siteid is a string (the site to load) and not
 * a form element.
 */
function loadSite(siteid, siteIdElement, siteElement, userElement, passElement) {
  // do any preprocessing here

  serverRequest("load", // the resource to call
    { "siteid": siteid } // populate with any parameters the server needs
  ).then(function (result) {
    if (result.response.ok) {
      // do any work that needs to be done on success
      siteElement.value = result.json.site;
      // userdisplay refers to the DOM element that students will need to
      // update to show the data returned by the server.
      siteElement.value = result.json.site;
      userElement.value = result.json.siteuser;

      // Decrypt the site's password before displaying it
      var hexPWD32B = masterPWD.padEnd(32, '0').convertToHex();
      decrypt(result.json.sitepasswd, hexPWD32B, result.json.siteIV).then(function (plaintext) {
        passElement.value = plaintext;
      });

    } else {
      // on failure, show the login page and display any server status
      showContent("login");
      serverStatus(result);
    }
  });
}

/**
 * Called when the logout link is clicked.
 */
function logout() {
  // do any preprocessing needed

  // tell the server to log out
  serverRequest("logout", {}).then(function (result) {
    if (result.response.ok) {
      showContent("login");
    }
    serverStatus(result);
  });
}