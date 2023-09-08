// Insert CPEs and CPEs Children - Cypher Script
UNWIND [cpeFilesToImport] AS files
CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value RETURN value',
  '
    WITH value
    MERGE (cpe:CPE {
      uri: value.cpe23Uri
    })

    FOREACH (value_child IN value.cpe_name |
      MERGE (child:CPE {
        uri: value_child.cpe23Uri
      })
      MERGE (cpe)-[:parentOf]->(child)
    )
  ',
  {batchSize:1000, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;