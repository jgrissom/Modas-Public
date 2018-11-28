using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Modas.Models;

namespace Modas.Controllers
{
    [Route("api/[controller]")]
    public class EventController : Controller
    {
        private IEventRepository repository;
        public EventController(IEventRepository repo) => repository = repo;

        [HttpGet]
        // returns all events (unsorted)
        public IEnumerable<Event> Get() => repository.Events
            .Include(e => e.Location);

        [HttpGet("{id}")]
        // return specific event
        public Event Get(int id) => repository.Events
            .Include(e => e.Location)
            .FirstOrDefault(e => e.EventId == id);

        [HttpPost]
        // add event
        public Event Post([FromBody] Event evt) => repository.AddEvent(new Event
        {
            TimeStamp = evt.TimeStamp,
            Flagged = evt.Flagged,
            LocationId = evt.LocationId
        });

        [HttpPut]
        // update event
        public Event Put([FromBody] Event evt) => repository.UpdateEvent(evt);

        [HttpDelete("{id}")]
        // delete event
        public void Delete(int id) => repository.DeleteEvent(id);
    }
}
