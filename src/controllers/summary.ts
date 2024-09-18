import { NextFunction, Request, Response } from "express";
import moment from "moment";
import { eachDayOfInterval, differenceInDays, format, isSameDay, subDays } from "date-fns";
import prismaClient from "../libs/prismadb";

export const all =
  async (req: Request, res: Response, next: NextFunction) => {
    const { from: fromDate, to: toDate } = req.query;

    const defaultTo = new Date();
    const defaultFrom = subDays(defaultTo, 30);

    const from = fromDate ? moment(fromDate.toString(), 'YYYY-MM-DD').toDate() : defaultFrom;
    const to = toDate ? moment(toDate.toString(), 'YYYY-MM-DD').toDate() : defaultTo;

    //Get the number of full days between the end and start dates.
    const periodLenght = differenceInDays(to, from) + 1;

    //Last period date for data comparaison with current date 
    const lastPeriodFrom = subDays(from, periodLenght);
    const lastPeriodTo = subDays(to, periodLenght);

    const currentPeriod = await fetchSummaryData(from, to);
    const lastPeriod = await fetchSummaryData(from, to);


    return res.status(200).json({
      success: true,
      data: {
        days: currentPeriod.days,
        transactions: {
          nber: currentPeriod.transactions,
          amount: currentPeriod.amountByStatus,
        },
        categories: {
          nber: currentPeriod.categories,
          amount: currentPeriod.categories_amount,
        },
        days_last: currentPeriod.days,
        transactions_last: {
          nber: lastPeriod.transactions,
          amount: lastPeriod.amountByStatus,
        },
        categories_last: {
          nber: lastPeriod.categories,
          amount: lastPeriod.categories_amount,
        },
      }

    });


  };

async function fetchSummaryData(from: Date, to: Date) {
  // Récupération du nombre de requêtes par statut
  const countByStatus = await prismaClient.transaction.groupBy({
    by: ['statusId'],
    where: {
      paymentDate: {
        gte: from,
        lte: to,
      },
    },
    _count: {
      id: true,
    },
    _sum: {
      amount: true,
    },
  });

  const transactions = countByStatus;

  const totalCount = countByStatus.reduce((acc, curr) => acc + curr._count.id, 0);

  const statusPercentages = countByStatus.map(item => ({
    status: item.statusId,
    percentage: (item._count.id / totalCount) * 100
  }));

  // Récupération du nombre total de requêtes
  const totalRequestCount = await prismaClient.transaction.count({
    where: {
      paymentDate: {
        gte: from,  // Date de début
        lte: to     // Date de fin
      }
    }
  });

  // Récupération du montant des requêtes par statut
  const sumAmountByStatus = await prismaClient.transaction.groupBy({
    by: ['statusId'],
    where: {
      createdAt: {
        gte: from,  // Date de début
        lte: to     // Date de fin
      }
    },
    _sum: {
      amount: true,  // Somme des montants
    },
  });

  const amountByStatus: any[] = [];
  // const amountByStatus = sumAmountByStatus.reduce((acc, curr) => {
  //   acc[curr.statusId] = curr._sum.amount;  // Utiliser _sum.amount ici
  //   return acc;
  // }, {});

  // console.log("amountByStatus", amountByStatus)
  //formatage pour l'api  
  const categories = countByStatus.map(categorie => {
    return {
      name: categorie.statusId,
      value: categorie._count,
    }
  });
  //formatage pour l'api
  const categories_amount = sumAmountByStatus.map(categorie => {
    return {
      name: categorie.statusId,
      value: categorie._sum,
    }
  });


  // Récupération des 10 principaux demandeurs de requêtes par statut
  // Étape 1: Récupérer les demandes
  const requesters = await prismaClient.transaction.findMany({
    where: {
      createdAt: {
        gte: from,  // Date de début
        lte: to     // Date de fin
      }
    },
    select: {
      status: true,
      userId: true,
    }
  });

  // Étape 2: Compter les demandes par utilisateur et statut
  // const requesterCounts = requesters.reduce((acc, { status, userId }) => {
  //   const key: string = `${status}_${userId}`;
  //   acc[key] = (acc[key] || 0) + 1;
  //   return acc;
  // }, {});

  // Étape 3: Regrouper par statut
  // const groupedByStatus = Object.entries(requesterCounts).reduce((acc, [key, count]) => {
  //   const [status, userId] = key;
  //   if (!acc[status]) {
  //     acc[status] = [];
  //   }
  //   acc[status].push({ userId, count });
  //   return acc;
  // }, {});

  // Étape 4: Obtenir les 10 meilleurs demandeurs par statut
  const topRequestersByStatus:any = [];
  // const topRequestersByStatus = Object.keys(groupedByStatus).map(status => ({
  //   status,
  //   topRequesters: groupedByStatus[status]
  //     .sort((a: { count: number; }, b: { count: number; }) => b.count - a.count) // Trier par compte
  //     .slice(0, 10) // Prendre les 10 meilleurs
  // }));
  const activeDays = await prismaClient.transaction.groupBy({
    by: ['createdAt'],
    where: {
      createdAt: {
        gte: from,  // Date de début
        lte: to     // Date de fin
      }
    },
    _count: {
      createdAt: true, // Compter les requêtes par jour
    },
    _sum: {
      amount: true,  // Somme des montants
    },
  });

  // Transformer les dates au format souhaité
  const formattedActiveDays = activeDays.map((day: any) => ({
    date: day.createdAt.toISOString().split('T')[0], // Format YYYY-MM-DD
    count: day._count.createdAt,
    totalAmount: day._sum.amount,
  }));


  const days: any = []; //fillMissingDays(activeDays, from, to);
  return {
    categories,
    categories_amount,
    transactions,
    totalRequestCount,
    amountByStatus,
    topRequestersByStatus,
    days
  }

}

export const me =
  async (req: Request, res: Response, next: NextFunction) => {

    //     // const from = new Date(req.body.from);
    //     // const to = new Date(req.body.to);
    //     const from = moment(req.body.from, 'DD/MM/YYYY').toDate();
    //     const to = moment(req.body.to, 'DD/MM/YYYY').toDate();
    //     const userId = req.user?.id;


    //     // Récupération du nombre de requêtes par statut
    //     const requestCountByStatus = await requestModel.aggregate([
    //       { $match: { payment_date: { $gte: from, $lte: to }, userId } },
    //       { $group: { _id: '$status', count: { $count: {} } } }
    //     ]);
    //     console.log("Voici", res.cookie)

    //     // Récupération du nombre total de requêtes
    //     const totalRequestCount = await requestModel.countDocuments({ payment_date: { $gte: from, $lte: to }, userId });

    //     // Récupération du montant des requêtes par statut
    //     const amountByStatus = await requestModel.aggregate([
    //       { $match: { createdAt: { $gte: from, $lte: to }, userId } },
    //       { $group: { _id: '$status', totalAmount: { $sum: '$amount' } } }
    //     ]);

    //     // Récupération des 10 principaux demandeurs de requêtes par statut
    //     // Étape 1: Récupérer les demandes dans la plage de dates spécifiée
    //     const requests = await prismaClient.tra.findMany({
    //       where: {
    //         createdAt: {
    //           gte: from,  // Date de début
    //           lte: to,    // Date de fin
    //         },
    //         userId: userId,  // Filtrer par userId
    //       },
    //       select: {
    //         status: true,
    //         userId: true,
    //       },
    //     });

    //     // Étape 2: Compter les demandes par utilisateur et statut
    //     const requesterCounts = requests.reduce((acc: { [x: string]: any; }, { status, userId }: any) => {
    //       const key = `${status}_${userId}`;
    //       acc[key] = (acc[key] || 0) + 1;
    //       return acc;
    //     }, {});

    //     // Étape 3: Regrouper par statut
    //     const groupedByStatus = Object.entries(requesterCounts).reduce((acc, [key, count]) => {
    //       const [status, userId] = key;
    //       if (!acc[status]) {
    //         acc[status] = [];
    //       }
    //       acc[status].push({ userId, count });
    //       return acc;
    //     }, {});

    //     // Étape 4: Obtenir les 10 meilleurs demandeurs par statut
    //     const topRequestersByStatus = Object.keys(groupedByStatus).map(status => ({
    //       status,
    //       topRequesters: groupedByStatus[status]
    //         .sort((a: { count: number; }, b: { count: number; }) => b.count - a.count) // Trier par compte
    //         .slice(0, 10) // Prendre les 10 meilleurs
    //     }));

    //     // Afficher le résultat
    //     console.log(topRequestersByStatus);

    //     return res.status(200).json({
    //       success: true,
    //       data: {
    //         requestCountByStatus,
    //         totalRequestCount,
    //         amountByStatus,
    //         topRequestersByStatus
    //       }
    //     });

  };


function calculatePercentageChange(
  current: number,
  previous: number
) {
  if (previous === 0) {
    return previous === current ? 0 : 100;
  }

  return ((current - previous) / previous) * 100;

};



function fillMissingDays(
  activeDays: { _id: string; count: number, totalAmount: number }[],
  startDate: Date,
  endDate: Date
): { date: Date; number: number }[] {
  if (activeDays.length === 0) return [];
  const allDays = eachDayOfInterval({
    start: startDate,
    end: endDate,
  });

  const transactionsByDay = allDays.map((day) => {
    const found = activeDays.find((d) => isSameDay(d._id, day));
    if (found) {
      return {
        date: day,
        number: found.count,
        amount: found.totalAmount,
      };
    } else {
      return {
        date: day,
        number: 0,
        amount: 0
      };
    }
  });

  return transactionsByDay;
}