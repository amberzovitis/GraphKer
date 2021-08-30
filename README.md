# GraphKer
Open Source Tool - Cybersecurity Graph Database in Neo4j


**|G|r|a|p|h|K|e|r**

 { open source tool for a cybersecurity graph database in neo4j }

With GraphKer you can have the most recent update of cyber-security vulnerabilities, weaknesses, attack patterns and platforms from MITRE and NIST, in an very useful and user friendly way provided by Neo4j graph databases!

# **Prerequisites**

_3 Steps to run GraphKer Tool_

1) Download and Install Neo4j Desktop
   - Windows Users: https://neo4j.com/download/
     - Create an account to get the license (totally free), download and install Neo4j Desktop. Useful Video: https://tinyurl.com/yjjbn8jx
   - Linux Users:
   
      ```
      sudo apt update
      sudo apt install apt-transport-https ca-certificates curl software-properties-common
      curl -fsSL https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
      sudo add-apt-repository "deb https://debian.neo4j.com stable 4.1"
      sudo apt install neo4j
      sudo systemctl enable neo4j.service
      sudo systemctl status neo4j.service
      ```
      
      You should have output that is similar to the following:
      ```
      ● neo4j.service - Neo4j Graph Database
     Loaded: loaded (/lib/systemd/system/neo4j.service; enabled; vendor preset: enabled)
     Active: active (running) since Fri 2020-08-07 01:43:00 UTC; 6min ago
     Main PID: 21915 (java)
     Tasks: 45 (limit: 1137)
     Memory: 259.3M
     CGroup: /system.slice/neo4j.service
     . . .
     ``` 
     Useful Video: https://tinyurl.com/vvpjf3dr
     
2) Create and Configure the Database
3) Install requirements.txt
   - **GraphKer Uses: xmltodict, neo4j, requests, beautifulsoup4**  




# 
--Search, Export Data and Analytics, Enrich your Skills--

**Created by Adamantios - Marios Berzovitis, Cybersecurity Expert MSc, BSc**

_Diploma Research - MSc @ Distributed Systems, Security and Emerging Information Technologies | University Of Piraeus_

_Co-Working with Cyber Security Research Lab | University Of Piraeus_

LinkedIn: https://tinyurl.com/p57w4ntu

Github: https://github.com/amberzovitis

Enjoy! Provide Feedback!
