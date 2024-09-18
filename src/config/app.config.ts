require("dotenv").config();

export const appConfig = {
    status : [
        'deleted', 
        "draft",
        "initiated",
        "validated",
        "rejected" , 
        "pending_commercial_input",
        "pending_finance_validation",
        "processing",
        "treated"   
    ]
}