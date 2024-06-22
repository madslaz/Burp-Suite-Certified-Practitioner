PortSwigger Article: [SQL Injection](https://portswigger.net/web-security/sql-injection)

## SQL injection vulnerability in WHERE clause allowing retrieval of hidden data 
- When user selects a category: `SELECT * FROM products WHERE category = 'Gifts' AND released = 1` /filter?category=Clothing%2c+shoes+and+accessories
- Solve the lab to display one or more unreleased products: `SELECT * FROM products WHERE category = '' OR 1=1 --'`/filter?category='+OR+1=1--
  - `--` is a comment indicator in SQL. Rest of the query is interpreted as a comment following this (effectively removing it). In this case, `AND released = 1` is removed. This could've been done just using the '--' to see unreleased items, but if you wanted to see unreleased items from all categories, the OR 1=1 --' works, as it is either Gifts or 1=1 is always true, the query returns all items. 
