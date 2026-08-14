# PostgreSQL Protocol 3.0 Documentation: protocol-message-types.html

> Source: [https://www.postgresql.org/docs/current/protocol-message-types.html](https://www.postgresql.org/docs/current/protocol-message-types.html)

---

|  |  |  |  |  |
| --- | --- | --- | --- | --- |
| Prev | Up | Chapter 54. Frontend/Backend Protocol | Home | Next |

  

---

  
    
      
        

## 54.6. Message Data Types #

      
    
  
  

This section describes the base data types used in messages.
  
    
      

**Int*
n

*(*
i

*)**
      **
: 
        

An *
n

*-bit integer in network byte order (most significant byte first). If *
i

* is specified it is the exact value that will appear, otherwise the value is variable. Eg. Int16, Int32(42).
      
      

**Int*
n

*[*
k

*]**
      **
: 
        

An array of *
k

* *
n

*-bit integers, each in network byte order. The array length *
k

* is always determined by an earlier field in the message. Eg. Int16[M].
      
      

**String(*
s

*)**
      **
: 
        

A null-terminated string (C-style string). There is no specific length limitation on strings. If *
s

* is specified it is the exact value that will appear, otherwise the value is variable. Eg. String, String("user").
        
          

### Note

          

*There is no predefined limit* on the length of a string that can be returned by the backend. Good coding strategy for a frontend is to use an expandable buffer so that anything that fits in memory can be accepted. If that's not feasible, read the full string and discard trailing characters that don't fit into your fixed-size buffer.
        
      
      

**Byte*
n

*(*
c

*)**
      **
: 
        

Exactly *
n

* bytes. If the field width *
n

* is not a constant, it is always determinable from an earlier field in the message. If *
c

* is specified it is the exact value. Eg. Byte2, Byte1('\n').
      
    
  

---

  

| Prev | Up | Next |
| --- | --- | --- |
| 54.5. Logical Streaming Replication Protocol | Home | 54.7. Message Formats |

          
          
            

## 

              

              If you see anything in the documentation that is not correct, does not match
              your experience with the particular feature or requires further clarification,
              please use
              this form
              to report a documentation issue.
              
            
          
         
      
    

    
    
      
      
        Policies |
        Code of Conduct |
        About PostgreSQL |
        Contact

        

Copyright © 1996-2026 The PostgreSQL Global Development Group
