# PostgreSQL Protocol 3.0 Documentation: protocol.html

> Source: [https://www.postgresql.org/docs/current/protocol.html](https://www.postgresql.org/docs/current/protocol.html)

---

|  |  |  |  |  |
| --- | --- | --- | --- | --- |
| Prev | Up | Part VII. Internals | Home | Next |

  

---

  
    
      
        

## Chapter 54. Frontend/Backend Protocol

      
    
  
  
    

**Table of Contents**
    
      

**54.1. Overview**
      **
: 
        
          

**54.1.1. Messaging Overview**
          

**54.1.2. Extended Query Overview**
          

**54.1.3. Formats and Format Codes**
          

**54.1.4. Protocol Versions**
        
      
      

**54.2. Message Flow**
      **
: 
        
          

**54.2.1. Start-up**
          

**54.2.2. Simple Query**
          

**54.2.3. Extended Query**
          

**54.2.4. Pipelining**
          

**54.2.5. Function Call**
          

**54.2.6. COPY Operations**
          

**54.2.7. Asynchronous Operations**
          

**54.2.8. Canceling Requests in Progress**
          

**54.2.9. Termination**
          

**54.2.10. SSL Session Encryption**
          

**54.2.11. GSSAPI Session Encryption**
        
      
      

**54.3. SASL Authentication**
      **
: 
        
          

**54.3.1. SCRAM-SHA-256 Authentication**
          

**54.3.2. OAUTHBEARER Authentication**
        
      
      

**54.4. Streaming Replication Protocol**
      

**54.5. Logical Streaming Replication Protocol**
      **
: 
        
          

**54.5.1. Logical Streaming Replication Parameters**
          

**54.5.2. Logical Replication Protocol Messages**
          

**54.5.3. Logical Replication Protocol Message Flow**
        
      
      

**54.6. Message Data Types**
      

**54.7. Message Formats**
      

**54.8. Error and Notice Message Fields**
      

**54.9. Logical Replication Message Formats**
      

**54.10. Summary of Changes since Protocol 2.0**
    
  
  

PostgreSQL uses a message-based protocol for communication between frontends and backends (clients and servers). The protocol is supported over TCP/IP and also over Unix-domain sockets. Port number 5432 has been registered with IANA as the customary TCP port number for servers supporting this protocol, but in practice any non-privileged port number can be used.
  

This document describes version 3.2 of the protocol, introduced in PostgreSQL version 18. The server and the libpq client library are backwards compatible with protocol version 3.0, implemented in PostgreSQL 7.4 and later.
  

In order to serve multiple clients efficiently, the server launches a new “backend” process for each client. In the current implementation, a new child process is created immediately after an incoming connection is detected. This is transparent to the protocol, however. For purposes of the protocol, the terms “backend” and “server” are interchangeable; likewise “frontend” and “client” are interchangeable.

---

  

| Prev | Up | Next |
| --- | --- | --- |
| 53.38. pg_wait_events | Home | 54.1. Overview |

          
          
            

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
