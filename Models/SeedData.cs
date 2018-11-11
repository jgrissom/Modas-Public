using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;

namespace Modas.Models
{
    // static class cannot be instantiated
    public static class SeedData
    {
        public static void EnsurePopulated(IApplicationBuilder app)
        {
            ApplicationDbContext context = app.ApplicationServices.GetRequiredService<ApplicationDbContext>();
            context.Database.Migrate();
            List<Location> Locations = new List<Location>();

            if (!context.Locations.Any())
            {
                Locations.Add(new Location { Name = "Front Door" });
                Locations.Add(new Location { Name = "Family Room" });
                Locations.Add(new Location { Name = "Rear Door" });
                // first, add Locations
                foreach (var l in Locations)
                {
                    context.Locations.Add(l);
                    context.SaveChanges();
                }
            }
            if (!context.Events.Any())
            {
                DateTime localDate = DateTime.Now;
                // subtract 6 months from date
                DateTime eventDate = localDate.AddMonths(-6);
                // random numbers will be needed
                Random rnd = new Random();
                // loop for each day in the range from 6 months ago to today
                while (eventDate < localDate)
                {
                    // random between 0 and 5 determines the number of events to occur on a given day
                    int num = rnd.Next(0, 6);

                    // a sorted list will be used to store daily events sorted by time
                    // each time an eventr is added, the list is re-sorted
                    SortedList<DateTime, Event> dailyEvents = new SortedList<DateTime, Event>();
                    // for loop to generate times for each event
                    for (int i = 0; i < num; i++)
                    {
                        // random between 0 and 23 for hour of the day
                        int hour = rnd.Next(0, 23);
                        // random between 0 and 59 for minute of the day
                        int minute = rnd.Next(0, 59);
                        // random between 0 and 59 for seconds of the day
                        int second = rnd.Next(0, 59);

                        // random location
                        int loc = rnd.Next(0, Locations.Count());

                        // generate event date/time
                        DateTime x = new DateTime(eventDate.Year, eventDate.Month, eventDate.Day, hour, minute, second);
                        // create event from date/time and location
                        Event e = new Event { TimeStamp = x, Flagged = false, Location = context.Locations.FirstOrDefault(l => l.Name == Locations[loc].Name) };
                        // add daily events to sorted list
                        dailyEvents.Add(e.TimeStamp, e);
                    }
                    // using sorted list for daily events, add to event list
                    foreach (var item in dailyEvents)
                    {
                        context.Events.Add(item.Value);
                        // save changes to database
                        context.SaveChanges();
                    }
                    // add 1 day
                    eventDate = eventDate.AddDays(1);
                }
            }
        }
    }
}
