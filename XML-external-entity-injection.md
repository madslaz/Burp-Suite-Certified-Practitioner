## Exploiting XXE using external entities to retrieve files
- This lab has a check stock feature that parses XML input and returns any unexpected values in the response. To solve the lab, inject an XML external entity to retrieve the contents of the `etc/passwd` file.
- Let's learn a bit about XXE at first. Web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows viewing of files on the application server filesystem. May also allow interaction with back-end or external systems that the application itself can access.
- Apps use XML format to transmit data between browser and server. Apps that do this virtually always use a standard library or platform API to process the XML data on the server. Vulns arise because the XML specification contains various potentially dangerous features, and standard parsers support these features even if they are not normally used by the app.
- XML external entities are a type of custom XML entity whose defined values are loaded from outside of the DTD in which they are declared. External entities are particularly interesting from a security perspective because they allow an entity to be defined based on the contents of a file path or URL.
  - [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp)
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId><storeId>2</storeId></stockCheck>
```

![image](https://github.com/user-attachments/assets/8b7cc000-507d-4896-95cc-c87e5ad1c674)
