// Insert CWEs Catalog - Cypher Script

UNWIND [cweReferenceFilesToImport] AS files
CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS reference RETURN reference',
  '
    // Insert External References for CWEs
    MERGE (r:External_Reference_CWE {Reference_ID: reference.Reference_ID})
      ON CREATE SET r.Author = [value IN reference.Author | value],
      r.Title = reference.Title,
      r.Edition = reference.Edition, r.URL = reference.URL,
      r.Publication_Year = reference.Publication_Year, r.Publisher = reference.Publisher
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;