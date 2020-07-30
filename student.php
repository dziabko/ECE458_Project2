<?php

/******************************************************************************
 * This file contains the server side PHP code that students need to modify 
 * to implement the password safe application.  Another PHP file, server.php,
 * must not be modified and handles initialization of some variables,
 * resource arbitration, and outputs the reponse.  The last PHP file is api.php
 * which also must not be modified by students and which provides an API
 * for resource functions to communicate with clients.
 * 
 * Student code in this file must only interact with the outside world via
 * the parameters to the functions.  These parameters are the same for each 
 * function.  The Request and Reponse classes can be found in api.php.
 * For more information on PDO database connections, see the documentation at
 * https://www.php.net/manual/en/book.pdo.php or other websites.
 *
 * The parameters to each function are:
 *   -- $request A Request object, passed by reference (see api.php)
 *   -- $response A Response object, passed by reference (see api.php)
 *   -- $db A PDO database connection, passed by reference
 *
 * The functions must also return the same values.  They are:
 *   -- true on success, false on failure
 *
 * Students should understand how to use the Request and Response objects, so
 * please spend some time looking at the code in api.php.  Apart from those
 * classes, the only other API function that students should use is the
 * log_to_console function, which MUST be used for server-side logging.
 *
 * The functions that need to be implemented all handle a specific type of
 * request from the client.  These map to the resources the client JavaScript
 * will call when the user performs certain actions.
 * The functions are:
 *    - preflight -- This is a special function in that it is called both 
 *                   as a separate "preflight" resource and it is also called
 *                   before every other resource to perform any preflight 
 *                   checks and insert any preflight response.  It is 
 *                   especially important that preflight returns true if the
 *                   request succeeds and false if something is wrong.
 *                   See server.php to see how preflight is called.
 *    - signup -- This resource should create a new account for the user
 *                if there are no problems with the request.
 *    - identify -- This resource identifies a user and returns any 
 *                  information that the client would need to log in.  You 
 *                  should be especially careful not to leak any information 
 *                  through this resource.
 *    - login -- This resource checks user credentials and, if they are valid,
 *               creates a new session.
 *    - sites -- This resource should return a list of sites that are saved
 *               for a logged in user.  This result is used to populate the 
 *               dropdown select elements in the user interface.
 *    - save -- This resource saves a new (or replaces an existing) entry in 
 *              the password safe for a logged in user.
 *    - load -- This resource loads an existing entry from the password safe
 *              for a logged in user.
 *    - logout -- This resource should destroy the existing user session.
 *
 * It is VERY important that resources set appropriate HTTP response codes!
 * If a resource returns a 5xx code (which is the default and also what PHP 
 * will set if there is an error executing the script) then we will assume  
 * there is a bug in the program during grading.  Similarly, if a resource
 * returns a 2xx code when it should fail, or a 4xx code when it should 
 * succeed, then I will assume it has done the wrong thing.
 *
 * You should not worry about the database getting full of old entries, so
 * don't feel the need to delete expired or invalid entries at any point.
 *
 * The database connection is to the sqlite3 database "passwordsafe.db".
 * The commands to create this database (and therefore its schema) can
 * be found in "initdb.sql".  You should familiarize yourself with this
 * schema.  Not every table or field must be used, but there are many 
 * helpful hints contained therein.
 * The database can be accessed to run queries on it with the command:
 *    sqlite3 passwordsafe.db
 * It is also easy to run SQL scripts on it by sending them to STDIN.
 *    sqlite3 passwordsafe.db < myscript.sql
 * This database can be recreated (to clean it up) by running:
 *    sqlite3 passwordsafe.db < dropdb.sql
 *    sqlite3 passwordsafe.db < initdb.sql
 *
 * This is outlined in more detail in api.php, but the Response object
 * has a few methods you will need to use:
 *    - set_http_code -- sets the HTTP response code (an integer)
 *    - success       -- sets a success status message
 *    - failure       -- sets a failure status message
 *    - set_data      -- returns arbitrary data to the client (in json)
 *    - set_cookie    -- sets an HTTP-only cookie on the client that
 *                       will automatically be returned with every 
 *                       subsequent request.
 *    - delete_cookie -- tells the client to delete a cookie.
 *    - set_token     -- passes a token (via data, not headers) to the
 *                       client that will automatically be returned with 
 *                       every subsequent request.
 *
 * A few things you will need to know to succeed:
 * ---------------------------------------------------
 * To get the current date and time in a format the database expects:
 *      $now = new DateTime();
 *      $now->format(DateTimeInterface::ISO8601);
 *
 * To get a date and time 15 minutes in the future (for the database):
 *      $now = new DateTime();
 *      $interval = new DateInterval("PT15M");
 *      $now->add($interval)->format(DateTimeInterface::ISO8601);
 *
 * Notice that, like JavaScript, PHP is loosely typed.  A common paradigm in
 * PHP is for a function to return some data on success or false on failure.
 * Care should be taken with these functions to test for failure using === 
 * (as in, if($result !== false ) {...}) because not using === or !== may 
 * result in unexpected ceorcion of a valid response (0) to false.
 * 
 *****************************************************************************/


/**
 * Performs any resource agnostic preflight validation and can set generic response values.
 * If the request fails any checks, preflight should return false and set appropriate
 * HTTP response codes and a failure message.  Returning false will prevent the requested
 * resource from being called.
 */
function preflight(&$request, &$response, &$db) {
  $response->set_http_code(200);
  $response->success("Request OK");
  log_to_console("OK");

  return true;
}

/**
 * Tries to sign up the username with the email and password.
 * The username and email must be unique and valid, and the password must be valid.
 * Note that it is fine to rely on database constraints.
 */
function signup(&$request, &$response, &$db) {
  $username = $request->param("username"); // The requested username from the client
  $password = $request->param("password"); // The requested password from the client
  $email    = $request->param("email");    // The requested email address from the client
  $fullname = $request->param("fullname"); // The requested full name from the client

  // SQL insert new user into user table
  $sql = 'INSERT into user (username, passwd, email, fullname) VALUES(:user_name,:pass_wd,:email,:full_name)';
  $stmt = $db->prepare($sql);
  $stmt->execute([
    ':user_name' => $username,
    ':pass_wd' => $password,
    ':email' => $email,
    ':full_name' => $fullname,
  ]);

  
  // Respond with a message of success.
  $response->set_http_code(201); // Created
  $response->success("Account created.");
  log_to_console("Account created.");

  return true;
}


/**
 * Handles identification requests.
 * This resource should return any information the client will need to produce 
 * a log in attempt for the given user.
 * Care should be taken not to leak information!
 */
function identify(&$request, &$response, &$db) {
  $username = $request->param("username"); // The username

  $response->set_http_code(200);
  $response->success("Successfully identified user.");
  log_to_console("Success.");

  return true;
}

/**
 * Handles login attempts.
 * On success, creates a new session.
 * On failure, fails to create a new session and responds appropriately.
 */
function login(&$request, &$response, &$db) {
  $username = $request->param("username"); // The username with which to log in
  $password = $request->param("password"); // The password with which to log in

  // TODO: HASH PASSWORD@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

  $fullname = "Default Full Name";


  // SQL checks whether user exists, and hashed passwords match
  // Query DB for (user,passwd)
  // $stm = $db->prepare('SELECT * from user WHERE username=? AND passwd=?');
  // $stm->bindValue(':userName', $username);
  // $stm->bindValue(':pass_wd', $password);

  // @@@@@
  $stm = $db->query('SELECT * FROM user WHERE username="'.$username.'" AND passwd="'.$password.'"');

  $result = $stm->fetchObject();
  log_to_console("Printing results for");
  log_to_console($username);
  log_to_console(serialize($result));
  log_to_console($result->email);

  $fullname = $result->fullname;


  // $result = $db->querySingle('SELECT email FROM user WHERE username="'.$username.'" AND passwd="'.$password.'"');


  // echo "@@@@@@@@@@@@@@@@@@@@@@BLAHHHHH\n";
  // log_to_console($result->fetchArray(SQLITE3_ASSOC));

  // If password and username dont match or dont exist
  if ($result->username == null) {
    log_to_console("USER DOESN't EXIST");
    $response->set_http_code(401); // OK
    $response->failure("Failed to login.");
    log_to_console("Failed to login.");
    return false;
  }else {
    log_to_console("USER EXISTS");
    $response->set_http_code(200); // Unauthorized user
    $response->set_data("fullname", $fullname); // Return the full name to the client for display
    $response->success("Successfully logged in.");

    // SQL insert new user into user_session table
    $sessionID = random_bytes(255);
    $sql = 'INSERT into user_session (sessionid, username, expires) VALUES(:session_id,:user_name,:expires)';
    $stmt = $db->prepare($sql);
    // $stmt->bindValue(':session_id', $sessionID, SQLITE3_TEXT);
    // $stmt->bindValue(':user_name', $username, SQLITE3_TEXT);
    // $stmt->bindValue(':expires', date("Y-m-d H:i:s", 0), SQLITE3_TEXT);
    $stmt->execute([
      ':session_id' => $sessionID,
      ':user_name' => $username,
      ":expires" => date("Y-m-d H:i:s", 0)
    ]);
    // $stmt->execute();


    $relative_time = 1000000000;
    // Create & send a cookie to the client
    $response->add_cookie("user_session_cookie", $sessionID, time() + $relative_time);

    log_to_console("Session created.");
    return true;
  }

  // log_to_console($res);

  // $sql = 'INSERT into user (username, passwd, email, fullname) VALUES(:user_name,:pass_wd,:email,:full_name)';
  // $stmt = $db->prepare($sql);
  // $stmt->execute([
  //   ':user_name' => $username,
  //   ':pass_wd' => $password,
  //   ':email' => $email,
  //   ':full_name' => $fullname,
  // ]);

}


/**
 * Returns the sites for which a password is already stored.
 * If the session is valid, it should return the data.
 * If the session is invalid, it should return 401 unauthorized.
 */
function sites(&$request, &$response, &$db) {
  // Retreive the sites associated with the current logged in user
  $cookie = $request->cookie("user_session_cookie"); // Get the user session cookie

  if ($cookie) {
    // First get the username from session cookie


    // @@@@@
    // log_to_console('SELECT username FROM user_session WHERE sessionid="'.$cookie.'"');
    // WORKS SOME OF THE TIME
    // $results = $db->query('SELECT username FROM user_session WHERE sessionid="'.$cookie.'"');

    $sql = 'SELECT username FROM user_session WHERE sessionid=:session_id';
    $results = $db->prepare($sql);
    $results->execute([
      ':session_id' => $cookie
    ]);


    // log_to_console('SELECT site FROM user_safe WHERE username="'.$username.'"');

    $result = $results->fetchObject();
    log_to_console("PRINTING RESULT for ");
    log_to_console($result->username);
    log_to_console(serialize($result));

    // GOT USERNAME@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    // GET site from user_safe using username


    $sql = 'SELECT * FROM user_safe WHERE username=:user_name';
    $results = $db->prepare($sql);
    $results->execute([
      ':user_name' => $result->username
    ]);

    log_to_console("PRINTING SITE RESULTS for ");

    // $blah_sites = [];
    $blah_sites = array();
    $blah_siteIDs = array();
    while ($row = $results->fetch(\PDO::FETCH_ASSOC)) {
      array_push($blah_sites, $row['site']);
      array_push($blah_siteIDs, $row['siteid']);
    }

    log_to_console(serialize($blah_sites));




    // log_to_console($results);

    // $fullname = $result->fullname;

    // $sites = array(
    //   "www.google.com"
    // );
    $sites = $blah_sites;

    // $siteids = array(
    //   5
    // );
    $siteids = $blah_siteIDs;

    // while ($row = $results->fetchObject()) {
    //   log_to_console("Adding row");
    //   $sites[] = [
    //     'siteids' => $row->siteid,
    //     'sites' => $row->site
    //   ];
    // }

    // log_to_console(serialize($sites));

    // while ($row = $results->fetchArray()) {
    //   log_to_console($row);
    // }
    

    $response->set_data("sites", $sites); // return the sites array to the client
    $response->set_data("siteids", $siteids); // return the sites array to the client
    $response->set_http_code(200);
    $response->success("Sites with recorded passwords.");
    log_to_console("Found and returned sites");

    return true;

  } else {
    $response->set_http_code(401);
    $response->failure("Unauthorize session.");
    log_to_console("Unauthorized session");

    return false;
  }
      
}

/**
 * Saves site and password data when passed from the client.
 * If the session is valid, it should save the data, overwriting the site if it exists.
 * If the session is invalid, it should return 401 unauthorized.
 */
function save(&$request, &$response, &$db) {
  $site       = $request->param("site");
  $siteuser   = $request->param("siteuser");
  $sitepasswd = $request->param("sitepasswd");

  // SQL insert new user into user table
  $sql = 'INSERT into user_safe (site, siteuser, sitepasswd) VALUES(:site,:siteuser,:sitepasswd)';
  $stmt = $db->prepare($sql);
  $stmt->execute([
    ':site' => $site,
    ':siteuser' => $siteuser,
    ':sitepasswd' => $sitepasswd,
  ]);
  

  $response->set_http_code(200); // OK
  $response->success("Save to safe succeeded.");
  log_to_console("Successfully saved site data");

  return true;
}

/**
 * Gets the data for a specific site and returns it.
 * If the session is valid and the site exists, return the data.
 * If the session is invalid return 401, if the site doesn't exist return 404.
 */
function load(&$request, &$response, &$db) {
  // Retreive the sites associated with the current logged in user
  $cookie = $request->cookie("user_session_cookie"); // Get the user session cookie

  if ($cookie) {
    // Get the site data from user_safe table using sideid from request
    $siteid = $request->param("siteid");

    // Query DB with siteid
    $stm = $db->query('SELECT * FROM user_safe WHERE siteid="'.$siteid.'"');


    $result = $stm->fetchObject();
    log_to_console(serialize($result));
  
    // $fullname = $result->fullname;

    // TODO: ENCRYPT SITE INFORMATION@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    // $site = $request->param("site");
    $site = $result->site;
    $response->set_data("site", $site);
    // $siteuser = $request->param("siteuser");
    $siteuser = $result->siteuser;
    $response->set_data("siteuser", $siteuser);
    // $sitepasswd = $request->param("sitepasswd");
    $sitepasswd = $result->sitepasswd;
    $response->set_data("sitepasswd", $sitepasswd);

    $response->set_http_code(200); // OK
    $response->success("Site data retrieved.");
    log_to_console("Successfully retrieved site data");

    return true;

  } else {
    $response->set_http_code(401);
    $response->failure("Unauthorize session.");
    log_to_console("Unauthorized session");

    return false;
  }
}

/**
 * Logs out of the current session.
 * Delete the associated session if one exists.
 */
function logout(&$request, &$response, &$db) {
  $response->set_http_code(200);
  $response->success("Successfully logged out.");
  log_to_console("Logged out");

  return true;
}
?>