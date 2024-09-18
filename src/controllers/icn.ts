import { NextFunction, Request, Response } from "express";
import fs from 'fs';
import path from 'path';
import moment from 'moment';

import { sqlQuery } from "../constants/request";
import prismaClient from "../libs/prismadb";
import { executeQuery, getConnection, releaseConnection } from "../libs/utils/db.oracle";
import BadRequestException from "../exceptions/bad-requests";
import { ErrorCode } from "../exceptions/http-exception";


//---------------------------------------------------------
//              GET ICN CODE 
//---------------------------------------------------------
export const generationOfIntegrationFile = 
  async (req: Request, res: Response, next: NextFunction) => {

      // Fetch data from the database
      // TODO : fix this part
      // const documents = await prismaClient.documents.findMany();

      // Création du contenu du fichier CSV
      let csvContent = `File Generated on=${moment().format('ddd MMM DD HH:mm:ss Z YYYY')}\nData for Date=${moment().format('DD/MM/YYYY')}|5701473|640816|3\n`;
      csvContent += 'Transaction_ID|Sub_transaction_Type|Bill_Partner_Company_name|Bill_partner_company_code|Bill_Number|Bill_Account_Number|Bill_Due_Date|Paid_Amount|Paid_Date|Paid_By_MSISDN|Transaction_Status|OM_Bill_Payment_Status\n';

      // TODO : fix this part
      // documents.forEach((doc) => {
      //   csvContent += `${doc.transaction_id}|${doc.sub_transaction_type}|${doc.bill_partner_company_name}|${doc.bill_partner_company_code}|${doc.bill_number}|${doc.bill_account_number}|${moment(doc.bill_due_date).format('DD/MM/YYYY HH:mm:ss')}|${doc.paid_amount}|${moment(doc.paid_date).format('DD/MM/YYYY HH:mm:ss')}|${doc.paid_by_msisdn}|${doc.transaction_status}|${doc.om_bill_payment_status}\n`;
      // });

      // Génération du nom de fichier
      const timestamp = moment().format('MMDDYYYYHHmmss');
      const fileName = `AES_${timestamp}_PAIDBILLS.csv`;

      // Génération du chemin du fichier
      const outputDir = path.join(__dirname, '../output');
      const filePath = path.join(outputDir, fileName);

      // Créer le répertoire 'output' s'il n'existe pas
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir);
      }

      // Écriture du fichier
      fs.writeFileSync(filePath, csvContent);


      // send the response
      return res.status(200).json({
        success: true,
        file: `CSV file generated at ${filePath}`
      });

  
  };


//---------------------------------------------------------
//              GET ICN CODE 
//---------------------------------------------------------
export const getICNNextCode =
  async (req: Request, res: Response, next: NextFunction) => {

    // Fetch data from the database
    const result = await executeQuery(sqlQuery.icn_next_code);

    // send the response
    return res.status(200).json({
      success: true,
      icn_code: result.rows[0][0] ?? ""
    });

  };

//---------------------------------------------------------
//              GET ICN DEMATERIALIZE CODE 
//---------------------------------------------------------
export const getICNDematerializeCode =
  async (req: Request, res: Response, next: NextFunction) => {

    // Fetch data from the database
    const result = await executeQuery(sqlQuery.icn_next_dematerialisation_code);

    // send the response
    return res.status(200).json({
      success: true,
      dematerialisation: result.rows[0][0] ?? ""
    });

  };


//---------------------------------------------------------
//              GET GROUPES
//---------------------------------------------------------
export const getICNGroupes =
  async (req: Request, res: Response, next: NextFunction) => {

    // Fetch data from the database
    const result = await executeQuery(sqlQuery.select_groupes);

    // send the response
    return res.status(200).json({
      success: true,
      groupes: result.rows
    });

  };

//---------------------------------------------------------
//              GET GROUPES
//---------------------------------------------------------
export const getICN =
  async (req: Request, res: Response, next: NextFunction) => {

    const { id: icn_number, type } = req.body
    // TODO :  Define the contraint due to the period 
    if (!icn_number) {
      throw new BadRequestException("Invalid parameters", ErrorCode.INVALID_DATA);
    }

    let query = "";
    let value: string[] = [];
    switch (type) {
      case "full":
        console.log("Full")
        query = sqlQuery.icn_fulldata
        value = [icn_number];
        break;
      case "light":
        console.log("Light")
        query = sqlQuery.icn_lightdata
        value = [icn_number, icn_number, icn_number];
        break;
      default:
        console.log("oTher")
        query = sqlQuery.icn_infos;
        value = [icn_number];
        break;
    }
    const result = await executeQuery(query, value);

    // send the response
    return res.status(200).json({
      success: true,
      data: result.rows
    });


  };
