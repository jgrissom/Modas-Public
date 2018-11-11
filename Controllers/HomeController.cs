using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Modas.Models;
using System.Linq;

namespace Modas.Controllers
{
    public class HomeController : Controller
    {
        private IEventRepository repository;
        public HomeController(IEventRepository repo)
        {
            repository = repo;
        }

        public ViewResult Index() => View(
            repository.Events.Include(e => e.Location).OrderBy(e => e.TimeStamp));
    }
}
