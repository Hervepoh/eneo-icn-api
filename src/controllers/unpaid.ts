import { NextFunction, Request, Response } from "express";

import { sqlQuery } from "../constants/request";
import { isEmpty } from "../libs/utils/formatter";
import { executeQuery, getConnection, releaseConnection } from "../libs/utils/db.oracle";
import { format } from "date-fns";
import InternalException from "../exceptions/internal-exception";
import { ErrorCode } from "../exceptions/http-exception";
import BadRequestException from "../exceptions/bad-requests";


//---------------------------------------------------------
//              get all Unpaid Bills Using Query Parameters
//---------------------------------------------------------
export const getUnpaidBills = async (req: Request, res: Response, next: NextFunction) => {


  // Get Query Parameters
  const { by: searchBy, type } = req.query;
  const searchType: string = type?.toString() ?? "one";
  // check user information
  const authorizeSearchBy: string[] = ["invoice", "contract", "regroup", "customer"];
  const authorizeType: string[] = ["many", "one"];
  const orderBy: string[] = ["asc", "desc"];
  const limit: string[] = ["10", "50", "100"];
  if (isEmpty(searchBy)) throw new BadRequestException("Invalid parameters", ErrorCode.INVALID_DATA);

  if (searchBy) {
    if (!authorizeSearchBy.includes(searchBy.toString())) {
      throw new BadRequestException("Invalid parameters", ErrorCode.INVALID_DATA);
    }
    if (!authorizeType.includes(searchType.toString())) {
      throw new BadRequestException("Invalid parameters", ErrorCode.INVALID_DATA);
    }
  }

  switch (searchBy) {
    case "invoice":
      getUnpaidBillsByInvoiceNumber(req, res, next);
      break;
    case "contract":
      getUnpaidBillsByContractNumber(req, res, next);
      break;
    case "regroup":
      getUnpaidBillsByCustomerRegroupNumber(req, res, next);
      break;
    case "customer":
      getUnpaidBillsByCustomerName(req, res, next);
      break;
    default:
      return res.status(200).json({
        success: true,
        bills: []
      });
      break;
  }
};


//---------------------------------------------------------
//              get all Unpaid Bills By Invoice Number 
//---------------------------------------------------------
export const getUnpaidBillsByInvoiceNumber =
  async (req: Request, res: Response, next: NextFunction) => {

    let connection;
    try {
      // Get Invoice Number from the query params 
      const { value: invoice_number } = req.query;

      // Fetch data from the database
      connection = await getConnection();
      const result = await connection.execute(sqlQuery.unpaid_bills_by_invoice_number, [invoice_number]);

      // send the response
      res.status(200).json({
        success: true,
        bills: result.rows
      });
    } catch (error: any) {
      // Catch the error and return and error respons
      throw new InternalException(error.message, error, ErrorCode.INTERNAL_EXCEPTION);
    } finally {
      // close the connection to the database
      if (connection) {
        await releaseConnection(connection);
      }
    }
  };


//---------------------------------------------------------
//              get all Unpaid Bills By Contract Number 
//---------------------------------------------------------
export const getUnpaidBillsByContractNumber =
  async (req: Request, res: Response, next: NextFunction) => {

    // Get date param from query parameters
    const { value: contract_number, from: FromDate, to: ToDate } = req.query;

    // TODO :  Define the contraint due to the period 
    if (isEmpty(contract_number) || isEmpty(FromDate) || isEmpty(ToDate)) {
      throw new BadRequestException("Invalid parameters", ErrorCode.INVALID_DATA);
    }
    if (!FromDate || !ToDate) {
      throw new BadRequestException("Invalid parameters", ErrorCode.INVALID_DATA);
    }

    // Fetch data from the database
    const result = await executeQuery(
      sqlQuery.unpaid_bills_by_contract_number,
      [
        contract_number,
        format(FromDate.toString(), "dd/MM/yyyy"),
        format(ToDate.toString(), "dd/MM/yyyy")
      ]
    );

    // send the response
    return res.status(200).json({
      success: true,
      bills: result.rows
    });


  };





//---------------------------------------------------------
//              get all Unpaid Bills By CustomerRegroup Number 
//---------------------------------------------------------
export const getUnpaidBillsByCustomerRegroupNumber =
  async (req: Request, res: Response, next: NextFunction) => {
    const { value, from: FromDate, to: ToDate } = req.query;
    // TODO :  Define the contraint due to the period 
    if (isEmpty(value) || isEmpty(FromDate) || isEmpty(ToDate)) {
      throw new BadRequestException("Invalid parameters", ErrorCode.INVALID_DATA);
    }
    if (!FromDate || !ToDate) {
      throw new BadRequestException("Invalid parameters", ErrorCode.INVALID_DATA);
    }

    // Fetch data from the database
    const result = await executeQuery(
      sqlQuery.unpaid_bills_by_customer_regroup_number,
      [
        value,
        format(FromDate.toString(), "dd/MM/yyyy"),
        format(ToDate.toString(), "dd/MM/yyyy")
      ]
    );

    return res.status(200).json({
      success: true,
      bills: result.rows
    });

  };

//---------------------------------------------------------
//              get all Unpaid Bills By Customer Name
//---------------------------------------------------------
export const getUnpaidBillsByCustomerName =
  async (req: Request, res: Response, next: NextFunction) => {
    const { value, from: FromDate, to: ToDate } = req.query;

    // TODO :  Define the contraint due to params
    if (isEmpty(value) || isEmpty(FromDate) || isEmpty(ToDate)) {
      throw new BadRequestException("Invalid parameters", ErrorCode.INVALID_DATA);
    }

    if (!FromDate || !ToDate) {
      throw new BadRequestException("Invalid parameters", ErrorCode.INVALID_DATA);
    }

    // Fetch data from the database
    const result = await executeQuery(
      sqlQuery.unpaid_bills_by_customer_name,
      [
        value,
        format(FromDate.toString(), "dd/MM/yyyy"),
        format(ToDate.toString(), "dd/MM/yyyy")
      ]
    );
    return res.status(200).json({
      success: true,
      bills: result.rows
    });

  };

//---------------------------------------------------------
//              get all Unpaid Bills On List
//---------------------------------------------------------
export const getUnpaidBillsOnList =
  async (req: Request, res: Response, next: NextFunction) => {

    // Fetch data from the database
    const result = await executeQuery(sqlQuery.unpaid_bills_on_list, []);

    return res.status(200).json({
      success: true,
      bills: result.rows
    });

  };


//---------------------------------------------------------
//              get all Unpaid Bills On List With Account
//---------------------------------------------------------
export const getUnpaidBillsOnListWithAccount =
  async (req: Request, res: Response, next: NextFunction) => {
    const { value, from: FromDate, to: ToDate } = req.body;

    // TODO :  Define the contraint due to the period 
    if (isEmpty(value) || isEmpty(FromDate) || isEmpty(ToDate)) {
      throw new BadRequestException("Invalid parameters", ErrorCode.INVALID_DATA);
    }
    // Fetch data from the database
    const result = await executeQuery(sqlQuery.unpaid_bills_on_list_with_account, [value, FromDate, ToDate]);

    return res.status(200).json({
      success: true,
      bills: result.rows
    });

  };
