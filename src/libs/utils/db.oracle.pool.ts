import { dbConfig } from "../../config/db.config";


var oracledb = require('oracledb');

async function getConnection() {
  try {
    await oracledb.createPool(dbConfig, (err: any) => {
      if (err) {
        console.error('Erreur de création du pool de connexions Oracle :', err);
        return;
      }
      console.log('Pool de connexions Oracle créé avec succès.');
    });
    return await oracledb.getConnection();
  } catch (err) {
    console.error('Erreur lors de l\'obtention d\'une connexion :', err);
    throw err;
  }
}


async function executeQuery(connection: any, query: string , values: any[]) {
  try {
    const result = await connection.execute(query);
    console.log('Résultat de la requête :', result);
  } catch (err) {
    console.error('Erreur lors de l\'exécution de la requête :', err);
    throw err;
  } finally {
    try {
      await connection.close();
    } catch (err) {
      console.error('Erreur lors de la fermeture de la connexion :', err);
    }
  }
}

// Function to close database pool 
async function releaseConnection() {
  try {
    await oracledb.getPool().close(0);
  } catch (err) {
    console.error('Erreur lors de la fermeture du pool de connexions :', err);
    throw err;
  }
}

async function run(query: string,values: any[]) {
  let connection
  try {
    const connection = await getConnection();
    let query = ''
    let values: any[] = [];
    await executeQuery(connection, query , values);
  } catch (err) {
    console.error('Erreur dans la fonction run :', err);
  } finally {
    if (connection) {
      await releaseConnection();
    }
  }
}