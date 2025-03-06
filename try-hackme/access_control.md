## Broken Access Control
Access control depends on 
- authentication and 
- session management

### Access control security models
types of models
1) **Programmatic access control**: controls are stored in db or someplace in the form of matrix
2) **Discretionary access control (DAC)**:access to resources or functions is constrained based upon users or named groups of users. Owners of resources or functions have the **ability to assign or delegate access permissions** to users
3) **Mandatory access control (MAC)**: is a centrally controlled system of access control in which access to some object (a file or other resource) by a subject is constrained. Significantly, unlike DAC the users and owners of resources have **no capability to delegate or modify access rights** for their resources
4) **Role-based access control (RBAC)**: named roles are defined to which access privileges are assigned. Users are then assigned to single or multiple roles. RBAC is most effective when there are sufficient roles to properly invoke access controls but not so many as to make the model excessively complex and unwieldy to manage. 

### Types of access controls
1) **Vertical access controls**:Vertical access controls are mechanisms that restrict access to sensitive functionality to specific types of users. For example, an administrator might be able to modify or delete any user's account, while an ordinary user has no access to these actions
2) **Horizontal access controls**: Horizontal access controls are mechanisms that restrict access to resources to specific users. 
3) **Context-dependent access controls**: Context-dependent access controls restrict access to functionality and resources based upon the state of the application or the user's interaction with it. 


### Examples of broken access controls
1) **Vertical privilege escalation**: If a user can gain access to functionality that they are not permitted to access then this is vertical privilege escalation. For example, if a non-administrative user can gain access to an admin page where they can delete user accounts, then this is vertical privilege escalation. 
- **Unprotected functionality**: 
- **Parameter-based access control methods**: Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location. 
- **Broken access control resulting from platform misconfiguration** :
  - Application configuration might do the `DENY: POST, /admin/deleteUser, managers`
  - The front-end controls described in the previous sections restrict access based on the URL and HTTP method. Some websites tolerate different HTTP request methods when performing an action. If an attacker can use the GET (or another) method to perform actions on a restricted URL, they can bypass the access control that is implemented at the platform layer. 

  - **Broken access control resulting from URL-matching discrepancies**  : 
    - improper capitalisation of url leading to different path 
    - Similar discrepancies can arise if developers using the Spring framework have enabled the `useSuffixPatternMatch` option. This allows paths with an arbitrary file extension to be mapped to an equivalent endpoint with no file extension. In other words, a request to `/admin/deleteUser.anything` would still match the `/admin/deleteUser` pattern. Prior to Spring 5.3, this option is enabled by default. 
    - On other systems, you may encounter discrepancies in whether /admin/deleteUser and /admin/deleteUser/ are treated as distinct endpoints. In this case, you may be able to bypass access controls by appending a trailing slash to the path. 

2) **Horizontal privilege escalation**
3) **Horizontal to vertical privilege escalation**: Often, a horizontal privilege escalation attack can be turned into a vertical privilege escalation, by compromising a more privileged user.



### Testing steps:
**Unprotected functionality:** 
- directory search for sensitive location
- robot.txt to get sesistive information
- site.xml file
- Do grep search on the response of application for `admin`
- find hidden fields
  - A hidden field.
  - A cookie.
  - A preset query string parameter.
  - update form might be added with something like roles and that gets updated directly. 
    - Find the update endpoint
    - also find the what attribute form can take, maybe returned by some get request of extra attributes like role, isAdmin etc.
- check if `X-Original-URL` and `X-Rewrite-URL` or something similary can be passed to backend in bankend request.
    - it could be `http://127.0.0.1`
    - it could be `http://localhost`
    - it could be `/invalid` and actual route is `/`

- change request method for `POST` to `GET` or `POST` to `POSTX` to bypass application firewall restricted access and see if something changes
- Check if different capitalisation  of routes is giving different results that could be used to bypass WAF for admin user
  - Version springboot version < 5.3 has it enabled by default
  - check if  `/admin/deleteUser.anything` is different from `/admin/deleteUser` if not then problem and hence can be bypassed 
  - append `/` at end and check if byass happens e.g. `/admin/deleteUser/` or `/admin/deleteUser` are different or not

**Horizontal access controls:**
- check if you can access different userId page by
  - using the id of other user
  - using the name of other user
  - using GUID of another user. And guid of other user could be accessible on comments, feedback, blogs etc
  - capture if redirect happens in burp as this redirect page contains sensitive information

**Horizontal to vertical privilege escalation**
- Often, a horizontal privilege escalation attack can be turned into a vertical privilege escalation, by compromising a more privileged user.
  - check for different arguments with different value to gain different priviledged user
  - attack `id` with different admin names

- check if certain download functionality lets you download some other files
- Multi-step vulnerability:There are series of request to a update request like load user detail, update form , submit form. In this some steps might be secured but other might not be.
- Referer-based access control: check referer header contains `/admin` in the header or not or something similar. In these case copying the session id is faster to check for admin actions to be done by normal user