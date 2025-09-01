#### Lab: Reflected XSS into a JavaScript String with Single Quote and Backslash Escape
- I input 'test' in the Search function, and I noticed it was reflected: "0 search results for 'test'" - so let's take a look at the source code. 
```javascript
var searchTerms = 'test';
document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
                    
```