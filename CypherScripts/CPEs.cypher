// Insert CPEs and CPEs Children - Cypher Script
UNWIND [filesToImport] AS files
CALL apoc.load.json(files) YIELD value

// Insert Base Platform
UNWIND value.matches AS value_cpe
MERGE (cpe:CPE {
  uri: value_cpe.cpe23Uri
})

// Insert Children
FOREACH (value_child IN value_cpe.cpe_name |
  MERGE (child:CPE {
    uri: value_child.cpe23Uri
  })
  MERGE (cpe)-[:parentOf]->(child)
)