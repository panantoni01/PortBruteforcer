import gi  # nopep8
gi.require_version('Gtk', '3.0')  # nopep8
from gi.repository import Gtk
from sqlalchemy.orm import sessionmaker  # nopep8
from sqlalchemy import DateTime, Column, String, Integer, Boolean, create_engine  # nopep8
from sqlalchemy.ext.declarative import declarative_base  # nopep8

#############################################
# DATABASE:
#############################################

Base = declarative_base()


class Attack(Base):
    __tablename__ = "Attack"

    id = Column(Integer, primary_key=True)
    end_time = Column(DateTime, nullable=False)
    successful = Column(Boolean, nullable=False)
    ip = Column(String, nullable=False)
    service = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    login = Column(String, nullable=False)
    password = Column(String, nullable=True)
    total_tries = Column(Integer, nullable=False)


def init_database():
    """Initialize database and return session binded with it"""
    engine = create_engine('sqlite:///attacks.db', echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    return session

#############################################
# GTK:
#############################################


class AttackListBoxRow(Gtk.ListBoxRow):
    def __init__(self, attack):
        super().__init__()
        self.attack = attack

    def get_attack(self):
        return self.attack


def create_row(attack: Attack):
    row = AttackListBoxRow(attack)
    hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)

    hbox.pack_start(Gtk.Label(label=attack.ip, xalign=0), True, True, 0)
    hbox.pack_start(Gtk.Label(label=attack.end_time.strftime(
        "%d %b %Y %H:%M:%S"), xalign=0), True, True, 0)
    hbox.pack_start(Gtk.Label(label=attack.service, xalign=0), True, True, 0)

    row.add(hbox)
    return row


class GTKHandler:
    def __init__(self, session):
        self.session = session

        builder = Gtk.Builder()
        builder.add_from_file("project.glade")
        builder.connect_signals(self)

        self.window_main = builder.get_object("window_main")
        self.window_main.connect('destroy', Gtk.main_quit)

        self.window_details = builder.get_object("window_details")
        self.success_image = builder.get_object("image_success")
        self.labels = {"ip": builder.get_object("label_ip"),
                       "port": builder.get_object("label_port"),
                       "service": builder.get_object("label_service"),
                       "time": builder.get_object("label_time"),
                       "login": builder.get_object("label_login"),
                       "password": builder.get_object("label_password"),
                       "tries": builder.get_object("label_tries")}

        self.listbox_books = builder.get_object("listbox_books")
        attacks = self.session.query(Attack).all()
        for attack in attacks:
            self.listbox_books.add(create_row(attack))

    def on_button_back_clicked(self, button):
        self.widget_hide(self.window_details)

    def on_button_details_clicked(self, button):
        for label in self.labels.values():
            label.set_text("")

        row = self.listbox_books.get_selected_row()
        if row is None:
            return

        attack = row.get_attack()
        self.labels["ip"].set_text(attack.ip)
        self.labels["port"].set_text(str(attack.port))
        self.labels["service"].set_text(attack.service)
        self.success_image.set_from_stock(
            Gtk.STOCK_OK if attack.successful else Gtk.STOCK_STOP, Gtk.IconSize.SMALL_TOOLBAR)
        self.labels["time"].set_text(attack.end_time.strftime("%d %b %Y %H:%M:%S"))
        self.labels["login"].set_text(attack.login)
        self.labels["password"].set_text(attack.password if attack.password is not None else "?")
        self.labels["tries"].set_text(str(attack.total_tries))

        self.window_details.show_all()

    def on_button_delete_clicked(self, button):
        row = self.listbox_books.get_selected_row()
        if row is None:
            return

        attack = row.get_attack()
        self.session.query(Attack).filter(Attack.id == attack.id).delete(synchronize_session=False)
        self.session.commit()

        self.listbox_books.remove(row)
        self.window_main.show_all()

    def on_button_delete_all_clicked(self, button):
        self.session.query(Attack).delete(synchronize_session=False)
        self.session.commit()

        rows = self.listbox_books.get_children()
        for row in rows:
            self.listbox_books.remove(row)
        self.window_main.show_all()

    def widget_hide(self, widget, data=None):
        widget.hide()
        return True


def start_GUI(session):
    handler = GTKHandler(session)
    handler.window_main.show_all()
    Gtk.main()
