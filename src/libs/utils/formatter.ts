export function isEmpty(variable: any): boolean {
    if (variable === null || variable === undefined || variable === '') {
      return true;
    }
    return false;
  }


export const formatDate = (value : string)=>{
    const date = new Date(value);
    const month = date.getMonth() + 1; // Add 1 because month values are zero-based
    const day = date.getDate();
    const year = date.getFullYear();
    const formattedDate = `${day}/${month}/${year}`;

   return(formattedDate);
}

// Function to get the date in the format "MMYY"
export const getCurrentMonthYear = (value : string) => {
  const currentDate = new Date(value);
  const month = String(currentDate.getMonth() + 1).padStart(2, '0');
  const year = String(currentDate.getFullYear()).slice(2);
  return `${month}${year}`;
};

export const parseDMY = (s:string) : Date => {
  let [d, m, y] = s.split(/\D/);
  return new Date(parseInt(y), parseInt(m)-1, parseInt(d));
};