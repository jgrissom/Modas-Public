using System.Collections.Generic;
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
    }
}
