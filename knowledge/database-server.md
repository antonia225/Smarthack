---
id: "database-server"
license: "CC-BY-SA-4.0"
attribution: "Wikipedia contributors, Database server; see source page history"
codes: ["DB_EXPOSED"]
keywords_en: ["database server", "mysql", "postgresql", "redis", "mongodb"]
keywords_ro: ["bază de date", "baze de date", "server de date"]
source_url: "https://en.wikipedia.org/wiki/Database_server"
fetched_url: "https://en.wikipedia.org/w/api.php?action=query&format=json&formatversion=2&prop=extracts%7Crevisions&explaintext=1&exsectionformat=plain&rvprop=ids%7Ctimestamp&redirects=1&titles=Database+server"
revision: {"sha256": "d7527b86ac8b949f0f898b34cad1efc0f2573ef6a3211f9babaca035a5174930", "etag": null, "last_modified": null, "id": 1353244672, "timestamp": "2026-05-09T02:39:49Z", "title": "Database server"}
retrieved: "2026-11-07T23:18:24.769232+00:00"
title: "Database server"
language: "en"
---

## kb:database-server#1

A database server is a server which uses a database application that provides database services to other computer programs or to computers, as defined by the client–server model. Database management systems (DBMSs) frequently provide database-server functionality, and some database management systems (such as MySQL) rely exclusively on the client–server model for database access (while others, like SQLite, are meant for use as an embedded database). Users access a database server either through a "front end" running on the user's computer – which displays requested data – or through the "back end", which runs on the server and handles tasks such as data analysis and storage. In a master–slave model, database master servers are central and primary locations of data while database slave servers are synchronized backups of the master acting as proxies. Most database applications respond to a query language. Each database understands its query language and converts each submitted query to server-readable form and executes it to retrieve results. Examples of proprietary database applications include Oracle, IBM Db2, Informix, and Microsoft SQL Server. Examples of

## kb:database-server#2

free software database applications include PostgreSQL; and under the GNU General Public Licence include Ingres and MySQL. Every server uses its own query logic and structure. The SQL (Structured Query Language) query language is more or less the same on all relational database applications. For clarification, a database server is simply a server that maintains services related to clients via database applications. DB-Engines lists over 300 DBMSs in its ranking. History The foundations for modeling large sets of data were first introduced by Charles Bachman in 1969. Bachman introduced Data Structure Diagrams (DSDs) as a means to graphically represent data. DSDs provided a means to represent the relationships between different data entities. In 1970, Codd introduced the concept that users of a database should be ignorant of the "inner workings" of the database. Codd proposed the "relational view" of data which later evolved into the Relational Model which most databases use today. In 1971, the Database Task Report Group of CODASYL (the driving force behind the development of the programming language COBOL) first proposed a "data

## kb:database-server#3

description language for describing a database, a data description language for describing that part of the data base known to a program, and a data manipulation language." Most of the research and development of databases focused on the relational model during the 1970s. Core Concepts and Operation A database and a server are distinct things A server is a networked computer (hardware or software) that manages resources, while a database is the structured collection of data stored within it. The "database server" is the specific software and/or hardware dedicated to running the database management system (DBMS). Users don't typically connect directly Most end-users interact with a front-end application (like a website or mobile app) which, in turn, communicates with the database server on their behalf. SQL is only a part of the picture SQL is the standard language for querying and manipulating data in relational databases, but by itself, it's virtually useless. It needs to be integrated within a broader application ecosystem (middleware, reporting tools, etc.) to provide actual functionality. Performance is often CPU-bound, not I/O-bound

## kb:database-server#4

A well-tuned database spends most of its time processing data in memory (RAM), not waiting for data to be read from disks. If a database is I/O-bound (slow disk access), it often indicates a schema problem or poor query optimization. "Serverless" databases still run on servers The term "serverless" in the context of cloud databases means the user doesn't have to manage the underlying physical infrastructure; the cloud provider handles the scaling and maintenance automatically, but physical servers are still doing the work. In 1975, Bachman demonstrated how the relational model and the data structure set were similar and "congruent" ways of structuring data while working for Honeywell. The entity–relationship model was first proposed in its current form by Peter Chen in 1976 while he was conducting research at MIT. This model became the most frequently used model to describe relational databases. Chen was able to propose a model that was superior to the navigational model and was more applicable to the "real world" than the relational model proposed by Codd. See also Database replication References
