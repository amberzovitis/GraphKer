// ------------------------------------------------------------------------
// Insert Weaknesses for CWEs
UNWIND [cweWeaknessFilesToImport] AS files
CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS weakness RETURN weakness',
  '
    // Insert CWEs
    MERGE (w:CWE {
      Name: "CWE-" + weakness.ID
    })
    SET w.Extended_Name = weakness.Name,
      w.Abstraction = weakness.Abstraction,
      w.Structure = weakness.Structure,
      w.Status = weakness.Status,
      w.Description = weakness.Description,
      w.Extended_Description = CASE apoc.meta.type(weakness.Extended_Description)
        WHEN "STRING"  THEN apoc.convert.toString(weakness.Extended_Description)
        WHEN "MAP" THEN apoc.convert.toString(weakness.Extended_Description.`xhtml:p`)
        ELSE null
      END,
      w.Likelihood_Of_Exploit = weakness.Likelihood_Of_Exploit,
      w.Background_Details = apoc.convert.toString(weakness.Background_Details.Background_Detail),
      w.Modes_Of_Introduction = [value IN weakness.Modes_Of_Introduction.Introduction | value.Phase],
      w.Submission_Date = weakness.Content_History.Submission.Submission_Date,
      w.Submission_Name = weakness.Content_History.Submission.Submission_Name,
      w.Submission_Organization = weakness.Content_History.Submission.Submission_Organization,
      w.Modifications = [value IN weakness.Content_History.Modification | apoc.convert.toString(value)],
      w.Alternate_Terms = apoc.convert.toString(weakness.Alternate_Terms),
      w.Notes = [value IN weakness.Notes.Note | apoc.convert.toString(value)],
      w.Affected_Resources = [value IN weakness.Affected_Resources.Affected_Resource | value],
      w.Functional_Areas = [value IN weakness.Functional_Areas.Functional_Area | value]

    // Insert Related Weaknesses CWE --> CWE
    WITH w, weakness
    FOREACH (Rel_Weakness IN weakness.Related_Weaknesses.Related_Weakness |
      MERGE (cwe:CWE {Name: "CWE-" + Rel_Weakness.CWE_ID})
      MERGE (w)-[:Related_Weakness {Nature: Rel_Weakness.Nature}]->(cwe)
    )

    // Insert Applicable Platforms for CWEs
    WITH w, weakness
    FOREACH (lg IN weakness.Applicable_Platforms.Language |
      MERGE (ap:Applicable_Platform {Type: "Language", Prevalence: lg.Prevalence,
                                    Name: coalesce(lg.Name, " NOT SET "), Class: coalesce(lg.Class, " NOT SET ")})
      MERGE (w)-[:Applicable_Platform]->(ap)
    )

    WITH w, weakness
    FOREACH (tch IN weakness.Applicable_Platforms.Technology |
      MERGE (ap:Applicable_Platform {Type: "Technology", Prevalence: tch.Prevalence,
                                    Name: coalesce(tch.Name, " NOT SET "), Class: coalesce(tch.Class, " NOT SET ")})
      MERGE (w)-[:Applicable_Platform]->(ap)
    )
    
    WITH w, weakness
    FOREACH (arc IN weakness.Applicable_Platforms.Architecture |
      MERGE (ap:Applicable_Platform {Type: "Architecture", Prevalence: arc.Prevalence,
                                    Name: coalesce(arc.Name, " NOT SET "), Class: coalesce(arc.Class, " NOT SET ")})
      MERGE (w)-[:Applicable_Platform]->(ap)
    )

    WITH w, weakness
    FOREACH (os IN weakness.Applicable_Platforms.Operating_System |
      MERGE (ap:Applicable_Platform {Type: "Operating System", Prevalence: os.Prevalence,
                                    Name: coalesce(os.Name, " NOT SET "), Class: coalesce(os.Class, " NOT SET ")})
      MERGE (w)-[:Applicable_Platform]->(ap)
    )

    // Insert Demonstrative Examples for CWEs
    WITH w, weakness
    FOREACH (example IN weakness.Demonstrative_Examples.Demonstrative_Example |
      MERGE (ex:Demonstrative_Example {
        Intro_Text: apoc.convert.toString(example.Intro_Text)
      })
      MERGE (w)-[r:hasExample]->(ex)
      SET r.Body_Text = [value IN example.Body_Text | apoc.convert.toString(value)],
      r.Example_Code = [value IN example.Example_Code | apoc.convert.toString(value)]
    )

    // Insert Consequences for CWEs
    WITH w, weakness
    FOREACH (consequence IN weakness.Common_Consequences.Consequence |
      MERGE (con:Consequence {Scope: [value IN consequence.Scope | value]})
      MERGE (w)-[rel:hasConsequence]->(con)
      SET rel.Impact = [value IN consequence.Impact | value],
      rel.Note = consequence.Note, rel.Likelihood = consequence.Likelihood
    )

    // Insert Detection Methods for CWEs
    WITH w, weakness
    FOREACH (dec IN weakness.Detection_Methods.Detection_Method |
      MERGE (d:Detection_Method {
        Method: dec.Method
      })
      MERGE (w)-[wd:canBeDetected]->(d)
      SET wd.Description = CASE apoc.meta.type(dec.Description)
        WHEN "STRING"  THEN apoc.convert.toString(dec.Description)
        WHEN "MAP" THEN apoc.convert.toString(dec.Description.`xhtml:p`)
        ELSE null
      END
      SET wd.Effectiveness = dec.Effectiveness,
      wd.Effectiveness_Notes = CASE apoc.meta.type(dec.Effectiveness_Notes)
        WHEN "STRING"  THEN apoc.convert.toString(dec.Effectiveness_Notes)
        WHEN "MAP" THEN apoc.convert.toString(dec.Effectiveness_Notes.`xhtml:p`)
        ELSE null
      END,
      wd.Detection_Method_ID = dec.Detection_Method_ID
    )

    // Insert Potential Mitigations for CWEs
    WITH w, weakness
    FOREACH (mit IN weakness.Potential_Mitigations.Mitigation |
      MERGE (m:Mitigation {Description: apoc.convert.toString(mit.Description)})
      SET m.Phase = [value IN mit.Phase | value],
        m.Strategy = mit.Strategy,
        m.Effectiveness = mit.Effectiveness, 
        m.Effectiveness_Notes = CASE apoc.meta.type(mit.Effectiveness_Notes)
          WHEN "STRING"  THEN apoc.convert.toString(mit.Effectiveness_Notes)
          WHEN "MAP" THEN apoc.convert.toString(mit.Effectiveness_Notes.`xhtml:p`)
        ELSE null
      END,
      m.Mitigation_ID = mit.Mitigation_ID
      MERGE (w)-[:hasMitigation]->(m)
    )

    // Insert Related Attack Patterns - CAPEC for CWEs
    WITH w, weakness
    FOREACH (rap IN weakness.Related_Attack_Patterns.Related_Attack_Pattern |
      MERGE (cp:CAPEC {
        Name: "CAPEC-" + rap.CAPEC_ID
      })
      MERGE (w)-[:RelatedAttackPattern]->(cp)
    )

    // Public References for CWEs
    WITH w, weakness
    FOREACH (exReference IN weakness.References.Reference |
      MERGE (ref:External_Reference_CWE {Reference_ID: exReference.External_Reference_ID})
      MERGE (w)-[:hasExternal_Reference]->(ref)
    )
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;